from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import CVE, OperationalAlertState, OperationalMetric, PublicationEvent
from cve_service.models.enums import CveState, EvidenceSignal, EvidenceSourceType, EvidenceStatus, PublicationEventStatus
from cve_service.services.alerting import (
    ALERT_STATUS_ACTIVE,
    RULE_X_PUBLISH_FAILURE,
    RULE_X_RATE_LIMIT,
    RULE_X_RECONCILIATION_REQUIRED,
    evaluate_operational_alerts,
)
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publication import X_PUBLICATION_METRIC_KEY, prepare_update_publication, publish_initial_publication
from cve_service.services.publish_targets import PublishResponse, PublishTargetError


class PublishableProvider:
    def review(self, request):
        from cve_service.services.ai_review import AIProviderResponse

        return AIProviderResponse(
            model_name="mock-gpt",
            payload={
                "cve_id": request.request_payload["cve_id"],
                "enterprise_relevance_assessment": "enterprise_relevant",
                "exploit_path_assessment": "internet_exploitable",
                "confidence": 0.96,
                "reasoning_summary": "Publishable in enterprise deployments.",
            },
        )


class SuccessfulXTarget:
    def __init__(self, external_id: str) -> None:
        self.name = "x"
        self.external_id = external_id

    def publish(self, request):
        published_at = datetime(2026, 4, 4, 0, 0, tzinfo=UTC)
        return PublishResponse(
            external_id=self.external_id,
            published_at=published_at,
            response_payload={
                "target": "x",
                "root_post_id": self.external_id,
                "post_ids": [self.external_id],
            },
        )


class ReconciliationFailureXTarget:
    def __init__(self, external_id: str) -> None:
        self.name = "x"
        self.external_id = external_id
        self.calls = 0

    def publish(self, request):
        self.calls += 1
        raise PublishTargetError(
            "Partial X thread requires reconciliation",
            category="reconciliation_required",
            retryable=False,
            requires_reconciliation=True,
            retry_blocked=True,
            external_id=self.external_id,
            response_payload={"partial_post_ids": [self.external_id]},
        )


class RateLimitedXTarget:
    name = "x"

    def publish(self, request):
        raise PublishTargetError(
            "X rate limited the request",
            category="rate_limited",
            retryable=True,
            rate_limited=True,
            retry_after_seconds=60,
            response_payload={"rate_limit": {"remaining": "0"}},
        )


class PermanentFailureXTarget:
    name = "x"

    def publish(self, request):
        raise PublishTargetError(
            "X rejected the request",
            category="permanent_failure",
            retryable=False,
            status_code=403,
            response_payload={"response_body": {"errors": [{"message": "forbidden"}]}},
        )


def test_x_publication_preserves_remote_id_lineage_for_updates(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-6200")
        publish_initial_publication(
            session,
            "CVE-2026-6200",
            SuccessfulXTarget("x-root-6200"),
            attempted_at=datetime(2026, 4, 4, 0, 5, tzinfo=UTC),
        )
        record_evidence(
            session,
            _update_evidence_input(
                "CVE-2026-6200",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-6200",
                collected_at=datetime(2026, 4, 4, 0, 6, tzinfo=UTC),
                confidence=0.99,
                is_authoritative=True,
            ),
        )

        prepared = prepare_update_publication(session, "CVE-2026-6200", target_name="x")

    assert prepared.payload_snapshot["replay_context"]["baseline_publication"]["destination"] == "x"
    assert prepared.payload_snapshot["replay_context"]["baseline_publication"]["external_id"] == "x-root-6200"
    assert prepared.baseline_publication_event is not None
    assert prepared.baseline_publication_event.external_id == "x-root-6200"


def test_x_reconciliation_failure_blocks_rerun_and_persists_remote_id(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-6201")
        target = ReconciliationFailureXTarget("x-root-6201")

        first = publish_initial_publication(
            session,
            "CVE-2026-6201",
            target,
            attempted_at=datetime(2026, 4, 4, 0, 10, tzinfo=UTC),
        )
        second = publish_initial_publication(
            session,
            "CVE-2026-6201",
            target,
            attempted_at=datetime(2026, 4, 4, 0, 11, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-6201"))
        events = session.scalars(select(PublicationEvent)).all()

    assert first.published is False
    assert first.requires_reconciliation is True
    assert first.external_id == "x-root-6201"
    assert second.published is False
    assert second.retry_blocked is True
    assert second.attempt_count == 1
    assert target.calls == 1
    assert cve is not None
    assert cve.state is CveState.PUBLISH_PENDING
    assert len(events) == 1
    assert events[0].status is PublicationEventStatus.FAILED
    assert events[0].external_id == "x-root-6201"
    assert events[0].target_response["retry_blocked"] is True


def test_x_metrics_and_alerts_cover_failure_rate_limits_and_reconciliation(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-6202")
        _prepare_publish_pending_cve(session, "CVE-2026-6203")
        _prepare_publish_pending_cve(session, "CVE-2026-6204")

        publish_initial_publication(
            session,
            "CVE-2026-6202",
            RateLimitedXTarget(),
            attempted_at=datetime(2026, 4, 4, 0, 20, tzinfo=UTC),
        )
        publish_initial_publication(
            session,
            "CVE-2026-6203",
            PermanentFailureXTarget(),
            attempted_at=datetime(2026, 4, 4, 0, 21, tzinfo=UTC),
        )
        publish_initial_publication(
            session,
            "CVE-2026-6204",
            ReconciliationFailureXTarget("x-root-6204"),
            attempted_at=datetime(2026, 4, 4, 0, 22, tzinfo=UTC),
        )
        evaluation = evaluate_operational_alerts(
            session,
            evaluated_at=datetime(2026, 4, 4, 0, 23, tzinfo=UTC),
            trigger="test.phase6.x.alerts",
        )
        rate_limit_metric = _get_metric(
            session,
            X_PUBLICATION_METRIC_KEY,
            {"event_type": "INITIAL", "result": "rate_limited", "target_name": "x"},
        )
        permanent_metric = _get_metric(
            session,
            X_PUBLICATION_METRIC_KEY,
            {"event_type": "INITIAL", "result": "permanent_failure", "target_name": "x"},
        )
        reconciliation_metric = _get_metric(
            session,
            X_PUBLICATION_METRIC_KEY,
            {"event_type": "INITIAL", "result": "reconciliation_required", "target_name": "x"},
        )
        active_states = session.scalars(
            select(OperationalAlertState).where(OperationalAlertState.status == ALERT_STATUS_ACTIVE)
        ).all()

    assert rate_limit_metric is not None
    assert rate_limit_metric.total_count == 1
    assert rate_limit_metric.last_details["rate_limited"] is True

    assert permanent_metric is not None
    assert permanent_metric.total_count == 1
    assert permanent_metric.last_details["failure_category"] == "permanent_failure"

    assert reconciliation_metric is not None
    assert reconciliation_metric.total_count >= 1
    assert reconciliation_metric.last_details["requires_reconciliation"] is True

    active_rule_keys = {state.rule_key for state in active_states}
    assert RULE_X_RATE_LIMIT in active_rule_keys
    assert RULE_X_PUBLISH_FAILURE in active_rule_keys
    assert RULE_X_RECONCILIATION_REQUIRED in active_rule_keys
    assert set(evaluation.active_alert_keys) == {state.alert_key for state in active_states}


def _get_metric(session, metric_key: str, dimensions: dict[str, str]) -> OperationalMetric | None:
    normalized_dimensions = {key: dimensions[key] for key in sorted(dimensions)}
    dimension_key = hashlib.sha256(
        json.dumps(normalized_dimensions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return session.scalar(
        select(OperationalMetric)
        .where(
            OperationalMetric.metric_key == metric_key,
            OperationalMetric.dimension_key == dimension_key,
        )
        .limit(1)
    )


def _prepare_publish_pending_cve(session, cve_id: str) -> None:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 6 X publication fixture.",
            severity="CRITICAL",
            source_name="fixture-feed",
            source_modified_at=datetime(2026, 4, 4, 0, 0, tzinfo=UTC),
            vendor_name="Microsoft",
            product_name="Exchange Server",
        ),
    )
    record_evidence(
        session,
        EvidenceInput(
            cve_id=cve_id,
            signal_type=EvidenceSignal.POC,
            status=EvidenceStatus.PRESENT,
            source_name="trusted-poc-db",
            source_type=EvidenceSourceType.TRUSTED_POC,
            source_record_id=f"poc-{cve_id.lower()}",
            evidence_timestamp=datetime(2026, 4, 4, 0, 2, tzinfo=UTC),
            collected_at=datetime(2026, 4, 4, 0, 2, tzinfo=UTC),
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=0.95,
            raw_payload={"fixture": cve_id},
        ),
    )
    result = process_post_enrichment_workflow(
        session,
        cve_id,
        PublishableProvider(),
        requested_at=datetime(2026, 4, 4, 0, 3, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 4, 0, 3, tzinfo=UTC),
    )
    assert result.state is CveState.PUBLISH_PENDING


def _update_evidence_input(
    cve_id: str,
    *,
    signal_type: EvidenceSignal,
    status: EvidenceStatus,
    source_type: EvidenceSourceType,
    source_name: str,
    source_record_id: str,
    collected_at: datetime,
    confidence: float,
    is_authoritative: bool,
) -> EvidenceInput:
    return EvidenceInput(
        cve_id=cve_id,
        signal_type=signal_type,
        status=status,
        source_type=source_type,
        source_name=source_name,
        source_record_id=source_record_id,
        evidence_timestamp=collected_at,
        collected_at=collected_at,
        freshness_ttl_seconds=14 * 24 * 60 * 60,
        confidence=confidence,
        is_authoritative=is_authoritative,
        raw_payload={"fixture": cve_id, "signal_type": signal_type.value},
    )
