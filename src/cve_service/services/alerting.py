from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import (
    AIReview,
    AuditEvent,
    CVE,
    CVEIngestionSnapshot,
    OperationalAlertState,
    OperationalAlertTransition,
    OperationalMetric,
    PublicationEvent,
)
from cve_service.models.enums import PublicationEventStatus

ALERT_RULE_VERSION = "phase5-alert-rules.v1"
AI_SCHEMA_VALIDATION_METRIC_KEY = "phase5.ai_review.validation.total"
STALE_REFRESH_METRIC_KEY = "phase5.stale_evidence.refresh.total"

ALERT_STATUS_ACTIVE = "ACTIVE"
ALERT_STATUS_RESOLVED = "RESOLVED"
TRANSITION_ACTIVATED = "ACTIVATED"
TRANSITION_RESOLVED = "RESOLVED"

INGEST_FRESHNESS_THRESHOLD = timedelta(hours=6)
AI_SCHEMA_LOOKBACK = timedelta(hours=1)
AI_SCHEMA_INVALID_MINIMUM = 2
AI_SCHEMA_INVALID_RATIO_THRESHOLD = 0.5
SOURCE_ERROR_BUDGET_LOOKBACK = timedelta(hours=24)
SOURCE_ERROR_BUDGET_AFFECTED_CVE_THRESHOLD = 2

RULE_INGEST_FRESHNESS = "phase5.ingest_freshness_breach"
RULE_DUPLICATE_PUBLISH_GUARD = "phase5.duplicate_publish_guard_breach"
RULE_AI_SCHEMA_FAILURE = "phase5.ai_schema_validation_failure_spike"
RULE_SOURCE_ERROR_BUDGET = "phase5.source_failure_error_budget_breach"

MANAGED_RULE_KEYS = {
    RULE_INGEST_FRESHNESS,
    RULE_DUPLICATE_PUBLISH_GUARD,
    RULE_AI_SCHEMA_FAILURE,
    RULE_SOURCE_ERROR_BUDGET,
}


@dataclass(frozen=True, slots=True)
class AlertCondition:
    alert_key: str
    rule_key: str
    scope_key: str
    severity: str
    contract_key: str
    title: str
    summary: str
    runbook_path: str | None
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class OperationalAlertEvaluationResult:
    evaluated_at: datetime
    active_alert_keys: tuple[str, ...]
    activated_alert_keys: tuple[str, ...]
    resolved_alert_keys: tuple[str, ...]


def evaluate_operational_alerts(
    session: Session,
    *,
    evaluated_at: datetime | None = None,
    trigger: str = "manual",
) -> OperationalAlertEvaluationResult:
    session.flush()
    effective_evaluated_at = _normalize_datetime(evaluated_at) or datetime.now(UTC)
    metric_index = _load_metric_index(session)
    active_conditions = {
        condition.alert_key: condition
        for condition in (
            _evaluate_ingest_freshness_alerts(session, effective_evaluated_at)
            + _evaluate_duplicate_publish_guard_alerts(session, effective_evaluated_at)
            + _evaluate_ai_schema_validation_alerts(session, effective_evaluated_at, metric_index)
            + _evaluate_source_error_budget_alerts(session, effective_evaluated_at, metric_index)
        )
    }
    existing_states = {
        state.alert_key: state
        for state in session.scalars(
            select(OperationalAlertState).where(OperationalAlertState.rule_key.in_(tuple(sorted(MANAGED_RULE_KEYS))))
        ).all()
    }
    activated_alert_keys: list[str] = []
    resolved_alert_keys: list[str] = []

    for alert_key, condition in active_conditions.items():
        payload = {
            **condition.payload,
            "alert_key": condition.alert_key,
            "rule_key": condition.rule_key,
            "scope_key": condition.scope_key,
            "title": condition.title,
            "summary": condition.summary,
            "severity": condition.severity,
            "contract_key": condition.contract_key,
            "runbook_path": condition.runbook_path,
            "trigger": trigger,
            "evaluated_at": effective_evaluated_at.isoformat(),
        }
        state = existing_states.get(alert_key)
        if state is None:
            state = OperationalAlertState(
                alert_key=condition.alert_key,
                rule_key=condition.rule_key,
                scope_key=condition.scope_key,
                status=ALERT_STATUS_ACTIVE,
                severity=condition.severity,
                contract_key=condition.contract_key,
                rule_version=ALERT_RULE_VERSION,
                title=condition.title,
                summary=condition.summary,
                runbook_path=condition.runbook_path,
                current_payload=payload,
                first_activated_at=effective_evaluated_at,
                last_evaluated_at=effective_evaluated_at,
                last_transition_at=effective_evaluated_at,
                resolved_at=None,
            )
            session.add(state)
            session.flush()
            _record_alert_transition(
                session,
                state=state,
                transition_type=TRANSITION_ACTIVATED,
                status_before=None,
                status_after=ALERT_STATUS_ACTIVE,
                severity=condition.severity,
                evaluated_at=effective_evaluated_at,
                payload=payload,
            )
            existing_states[alert_key] = state
            activated_alert_keys.append(alert_key)
            continue

        if state.status != ALERT_STATUS_ACTIVE:
            status_before = state.status
            state.status = ALERT_STATUS_ACTIVE
            state.resolved_at = None
            state.last_transition_at = effective_evaluated_at
            state.first_activated_at = state.first_activated_at or effective_evaluated_at
            _record_alert_transition(
                session,
                state=state,
                transition_type=TRANSITION_ACTIVATED,
                status_before=status_before,
                status_after=ALERT_STATUS_ACTIVE,
                severity=condition.severity,
                evaluated_at=effective_evaluated_at,
                payload=payload,
            )
            activated_alert_keys.append(alert_key)

        state.rule_key = condition.rule_key
        state.scope_key = condition.scope_key
        state.severity = condition.severity
        state.contract_key = condition.contract_key
        state.rule_version = ALERT_RULE_VERSION
        state.title = condition.title
        state.summary = condition.summary
        state.runbook_path = condition.runbook_path
        state.current_payload = payload
        state.last_evaluated_at = effective_evaluated_at

    for alert_key, state in existing_states.items():
        if state.status != ALERT_STATUS_ACTIVE or alert_key in active_conditions:
            continue
        resolution_payload = {
            **state.current_payload,
            "trigger": trigger,
            "resolved_at": effective_evaluated_at.isoformat(),
        }
        state.status = ALERT_STATUS_RESOLVED
        state.last_evaluated_at = effective_evaluated_at
        state.last_transition_at = effective_evaluated_at
        state.resolved_at = effective_evaluated_at
        state.current_payload = resolution_payload
        _record_alert_transition(
            session,
            state=state,
            transition_type=TRANSITION_RESOLVED,
            status_before=ALERT_STATUS_ACTIVE,
            status_after=ALERT_STATUS_RESOLVED,
            severity=state.severity,
            evaluated_at=effective_evaluated_at,
            payload=resolution_payload,
        )
        resolved_alert_keys.append(alert_key)

    session.flush()
    return OperationalAlertEvaluationResult(
        evaluated_at=effective_evaluated_at,
        active_alert_keys=tuple(sorted(active_conditions)),
        activated_alert_keys=tuple(sorted(activated_alert_keys)),
        resolved_alert_keys=tuple(sorted(resolved_alert_keys)),
    )


def list_active_operational_alerts(session: Session) -> list[OperationalAlertState]:
    return session.scalars(
        select(OperationalAlertState)
        .where(OperationalAlertState.status == ALERT_STATUS_ACTIVE)
        .order_by(OperationalAlertState.rule_key.asc(), OperationalAlertState.alert_key.asc())
    ).all()


def _evaluate_ingest_freshness_alerts(session: Session, evaluated_at: datetime) -> list[AlertCondition]:
    latest_by_source: dict[str, tuple[str, CVEIngestionSnapshot]] = {}
    rows = session.execute(
        select(CVE.cve_id, CVEIngestionSnapshot)
        .join(CVEIngestionSnapshot, CVEIngestionSnapshot.cve_id == CVE.id)
        .where(CVEIngestionSnapshot.source_modified_at.is_not(None))
        .order_by(
            CVEIngestionSnapshot.source_name.asc(),
            CVEIngestionSnapshot.source_modified_at.desc(),
            CVEIngestionSnapshot.created_at.desc(),
            CVEIngestionSnapshot.id.desc(),
        )
    ).all()
    for public_cve_id, snapshot in rows:
        latest_by_source.setdefault(snapshot.source_name, (public_cve_id, snapshot))

    conditions: list[AlertCondition] = []
    for source_name, (public_cve_id, snapshot) in latest_by_source.items():
        lag = evaluated_at - _normalize_datetime(snapshot.source_modified_at)
        if lag <= INGEST_FRESHNESS_THRESHOLD:
            continue
        scope_key = f"source:{source_name}"
        conditions.append(
            AlertCondition(
                alert_key=_build_alert_key(RULE_INGEST_FRESHNESS, scope_key),
                rule_key=RULE_INGEST_FRESHNESS,
                scope_key=scope_key,
                severity="ERROR",
                contract_key="ingestion_freshness",
                title="Ingest Freshness Breach",
                summary=(
                    f"Source '{source_name}' exceeded the 6 hour freshness window with "
                    f"{int(lag.total_seconds())} seconds of lag."
                ),
                runbook_path="runbooks/ingestion-failure.md",
                payload={
                    "source_name": source_name,
                    "cve_id": public_cve_id,
                    "snapshot_id": str(snapshot.id),
                    "latest_source_modified_at": snapshot.source_modified_at.isoformat(),
                    "lag_seconds": int(lag.total_seconds()),
                    "threshold_seconds": int(INGEST_FRESHNESS_THRESHOLD.total_seconds()),
                },
            )
        )
    return conditions


def _evaluate_duplicate_publish_guard_alerts(session: Session, evaluated_at: datetime) -> list[AlertCondition]:
    rows = session.execute(
        select(CVE.cve_id, PublicationEvent)
        .join(PublicationEvent, PublicationEvent.cve_id == CVE.id)
        .where(PublicationEvent.status == PublicationEventStatus.PUBLISHED)
        .order_by(
            CVE.cve_id.asc(),
            PublicationEvent.event_type.asc(),
            PublicationEvent.destination.asc(),
            PublicationEvent.content_hash.asc(),
            PublicationEvent.published_at.asc(),
            PublicationEvent.id.asc(),
        )
    ).all()
    grouped_events: dict[tuple[str, str, str | None, str | None], list[PublicationEvent]] = defaultdict(list)
    for public_cve_id, event in rows:
        grouped_events[(public_cve_id, event.event_type.value, event.destination, event.content_hash)].append(event)

    conditions: list[AlertCondition] = []
    for (public_cve_id, event_type, destination, content_hash), events in grouped_events.items():
        if len(events) <= 1:
            continue
        scope_key = f"{public_cve_id}:{event_type}:{destination or 'unknown'}"
        conditions.append(
            AlertCondition(
                alert_key=_build_alert_key(RULE_DUPLICATE_PUBLISH_GUARD, scope_key),
                rule_key=RULE_DUPLICATE_PUBLISH_GUARD,
                scope_key=scope_key,
                severity="CRITICAL",
                contract_key="publish_idempotency",
                title="Duplicate Publish Guard Breach",
                summary=(
                    f"{public_cve_id} has {len(events)} published {event_type.lower()} events for "
                    f"target '{destination or 'unknown'}' with the same content hash."
                ),
                runbook_path="runbooks/publish-failure.md",
                payload={
                    "cve_id": public_cve_id,
                    "event_type": event_type,
                    "target_name": destination,
                    "content_hash": content_hash,
                    "duplicate_count": len(events),
                    "publication_event_ids": [str(event.id) for event in events],
                    "last_published_at": _serialize_datetime(max(event.published_at for event in events if event.published_at is not None)),
                    "evaluated_at": evaluated_at.isoformat(),
                },
            )
        )
    return conditions


def _evaluate_ai_schema_validation_alerts(
    session: Session,
    evaluated_at: datetime,
    metric_index: dict[str, list[OperationalMetric]],
) -> list[AlertCondition]:
    window_start = evaluated_at - AI_SCHEMA_LOOKBACK
    rows = session.execute(
        select(CVE.cve_id, AIReview)
        .join(AIReview, AIReview.cve_id == CVE.id)
        .where(AIReview.created_at >= window_start)
        .order_by(AIReview.created_at.asc(), AIReview.id.asc())
    ).all()
    attempted_reviews = [(public_cve_id, review) for public_cve_id, review in rows]
    invalid_reviews = [(public_cve_id, review) for public_cve_id, review in attempted_reviews if review.schema_valid is False]
    total_reviews = len(attempted_reviews)
    invalid_count = len(invalid_reviews)
    invalid_ratio = invalid_count / total_reviews if total_reviews else 0.0
    if invalid_count < AI_SCHEMA_INVALID_MINIMUM or invalid_ratio < AI_SCHEMA_INVALID_RATIO_THRESHOLD:
        return []
    return [
        AlertCondition(
            alert_key=_build_alert_key(RULE_AI_SCHEMA_FAILURE, "system"),
            rule_key=RULE_AI_SCHEMA_FAILURE,
            scope_key="system",
            severity="ERROR",
            contract_key="ai_schema_validation",
            title="AI Schema Validation Failure Spike",
            summary=(
                f"AI review schema validation failed {invalid_count} times out of {total_reviews} attempts "
                f"in the last hour."
            ),
            runbook_path=None,
            payload={
                "lookback_seconds": int(AI_SCHEMA_LOOKBACK.total_seconds()),
                "invalid_reviews": invalid_count,
                "total_reviews": total_reviews,
                "invalid_ratio": round(invalid_ratio, 4),
                "minimum_invalid_reviews": AI_SCHEMA_INVALID_MINIMUM,
                "invalid_ratio_threshold": AI_SCHEMA_INVALID_RATIO_THRESHOLD,
                "invalid_review_ids": [str(review.id) for _, review in invalid_reviews],
                "affected_cve_ids": sorted({public_cve_id for public_cve_id, _ in invalid_reviews}),
                "metric_totals": _serialize_metric_rows(metric_index.get(AI_SCHEMA_VALIDATION_METRIC_KEY, [])),
            },
        )
    ]


def _evaluate_source_error_budget_alerts(
    session: Session,
    evaluated_at: datetime,
    metric_index: dict[str, list[OperationalMetric]],
) -> list[AlertCondition]:
    window_start = evaluated_at - SOURCE_ERROR_BUDGET_LOOKBACK
    rows = session.execute(
        select(CVE.cve_id, AuditEvent)
        .join(CVE, AuditEvent.cve_id == CVE.id)
        .where(
            AuditEvent.event_type == "enrichment.refresh_evaluated",
            AuditEvent.created_at >= window_start,
        )
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
    ).all()

    grouped_events: dict[str, list[tuple[str, AuditEvent]]] = defaultdict(list)
    for public_cve_id, event in rows:
        source_name = str(event.details.get("selected_source_name") or "unknown-source")
        grouped_events[source_name].append((public_cve_id, event))

    conditions: list[AlertCondition] = []
    for source_name, events in grouped_events.items():
        affected_cve_ids = sorted({public_cve_id for public_cve_id, _ in events})
        if len(affected_cve_ids) < SOURCE_ERROR_BUDGET_AFFECTED_CVE_THRESHOLD:
            continue
        scope_key = f"source:{source_name}"
        signal_types = sorted({str(event.details.get("signal_type")) for _, event in events})
        conditions.append(
            AlertCondition(
                alert_key=_build_alert_key(RULE_SOURCE_ERROR_BUDGET, scope_key),
                rule_key=RULE_SOURCE_ERROR_BUDGET,
                scope_key=scope_key,
                severity="ERROR",
                contract_key="source_failure_error_budget",
                title="Source Error Budget Breach",
                summary=(
                    f"Source '{source_name}' forced stale-refresh reevaluation across {len(affected_cve_ids)} CVEs "
                    f"in the last 24 hours."
                ),
                runbook_path="runbooks/ingestion-failure.md",
                payload={
                    "source_name": source_name,
                    "lookback_seconds": int(SOURCE_ERROR_BUDGET_LOOKBACK.total_seconds()),
                    "affected_cve_ids": affected_cve_ids,
                    "affected_cve_count": len(affected_cve_ids),
                    "refresh_event_count": len(events),
                    "signal_types": signal_types,
                    "affected_cve_threshold": SOURCE_ERROR_BUDGET_AFFECTED_CVE_THRESHOLD,
                    "metric_totals": _serialize_metric_rows(metric_index.get(STALE_REFRESH_METRIC_KEY, [])),
                },
            )
        )
    return conditions


def _load_metric_index(session: Session) -> dict[str, list[OperationalMetric]]:
    metric_rows = session.scalars(
        select(OperationalMetric).where(
            OperationalMetric.metric_key.in_(
                (
                    AI_SCHEMA_VALIDATION_METRIC_KEY,
                    STALE_REFRESH_METRIC_KEY,
                )
            )
        )
    ).all()
    metric_index: dict[str, list[OperationalMetric]] = defaultdict(list)
    for metric in metric_rows:
        metric_index[metric.metric_key].append(metric)
    return metric_index


def _record_alert_transition(
    session: Session,
    *,
    state: OperationalAlertState,
    transition_type: str,
    status_before: str | None,
    status_after: str,
    severity: str,
    evaluated_at: datetime,
    payload: dict[str, Any],
) -> None:
    session.add(
        OperationalAlertTransition(
            alert_state_id=state.id,
            alert_key=state.alert_key,
            rule_key=state.rule_key,
            transition_type=transition_type,
            status_before=status_before,
            status_after=status_after,
            severity=severity,
            evaluated_at=evaluated_at,
            payload=payload,
        )
    )


def _serialize_metric_rows(metrics: list[OperationalMetric]) -> list[dict[str, Any]]:
    return [
        {
            "metric_key": metric.metric_key,
            "dimensions": dict(metric.dimensions),
            "total_count": metric.total_count,
            "first_observed_at": metric.first_observed_at.isoformat(),
            "last_observed_at": metric.last_observed_at.isoformat(),
            "last_details": dict(metric.last_details),
        }
        for metric in sorted(metrics, key=lambda metric: (metric.dimension_key, metric.metric_key))
    ]


def _build_alert_key(rule_key: str, scope_key: str) -> str:
    payload = json.dumps({"rule_key": rule_key, "scope_key": scope_key}, sort_keys=True, separators=(",", ":"))
    suffix = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"{rule_key}:{suffix}"


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_datetime(value: datetime | None) -> str | None:
    normalized = _normalize_datetime(value)
    return normalized.isoformat() if normalized is not None else None
