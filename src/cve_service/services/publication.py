from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import (
    AIReview,
    AuditEvent,
    CVE,
    CVEIngestionSnapshot,
    Classification,
    PolicyConfigurationSnapshot,
    PolicyDecision,
    PublicationEvent,
    UpdateCandidate,
)
from cve_service.models.enums import (
    AuditActorType,
    CveState,
    PolicyDecisionOutcome,
    PublicationEventStatus,
    PublicationEventType,
)
from cve_service.services.ai_review import fingerprint_payload
from cve_service.services.description_compression import (
    DescriptionCompressor,
    DescriptionCompressionRequest,
    fallback_description_brief,
)
from cve_service.services.operational_metrics import increment_operational_metric
from cve_service.services.publish_content import (
    PublishContent,
    build_initial_publish_content,
    build_update_publish_content,
)
from cve_service.services.publish_targets import PublishRequest, PublishTarget, PublishTargetError
from cve_service.services.state_machine import InvalidStateTransition, guard_transition

PUBLICATION_EVENT_SCHEMA_VERSION = "phase4-publication-event.v1"
UPDATE_PUBLICATION_EVENT_SCHEMA_VERSION = "phase5-update-publication-event.v1"
UPDATE_PUBLICATION_METRIC_KEY = "phase5.update_publication.outcomes.total"
X_PUBLICATION_METRIC_KEY = "phase6.x_publication.outcomes.total"
MAX_REFERENCE_LINKS_PER_CATEGORY = 2


@dataclass(frozen=True, slots=True)
class PreparedPublication:
    cve: CVE
    classification: Classification | None
    decision: PolicyDecision | None
    policy_snapshot: PolicyConfigurationSnapshot | None
    ai_review: AIReview | None
    target_name: str
    event_type: PublicationEventType
    content: PublishContent
    content_hash: str
    idempotency_key: str
    payload_snapshot: dict[str, Any]
    update_candidate: UpdateCandidate | None = None
    baseline_publication_event: PublicationEvent | None = None


PreparedInitialPublication = PreparedPublication
PreparedUpdatePublication = PreparedPublication


@dataclass(frozen=True, slots=True)
class PublicationResult:
    cve_id: str
    state: CveState
    decision_id: UUID | None
    event_id: UUID
    event_type: PublicationEventType
    event_status: PublicationEventStatus
    target_name: str
    content_hash: str
    idempotency_key: str
    published: bool
    duplicate_blocked: bool
    retry_blocked: bool
    reused_event: bool
    attempt_count: int
    external_id: str | None
    failure_category: str | None
    retryable: bool
    requires_reconciliation: bool
    rate_limited: bool


def prepare_publication(
    session: Session,
    cve_id: str,
    *,
    target_name: str,
    description_compressor: DescriptionCompressor | None = None,
) -> PreparedPublication:
    cve = _get_cve_by_public_id(session, cve_id)
    if cve.state is CveState.UPDATE_PENDING:
        return prepare_update_publication(session, cve_id, target_name=target_name)
    return prepare_initial_publication(
        session,
        cve_id,
        target_name=target_name,
        description_compressor=description_compressor,
    )


def prepare_initial_publication(
    session: Session,
    cve_id: str,
    *,
    target_name: str,
    description_compressor: DescriptionCompressor | None = None,
) -> PreparedInitialPublication:
    cve = _get_cve_by_public_id(session, cve_id)
    classification = _get_latest_classification(session, cve.id)
    if classification is None:
        raise ValueError(f"no classification found for {cve_id}")

    decision = _get_latest_policy_decision(session, cve.id)
    if decision is None:
        raise ValueError(f"no policy decision found for {cve_id}")
    if decision.decision is not PolicyDecisionOutcome.PUBLISH:
        raise ValueError(f"latest policy decision is not publishable for {cve_id}")
    if cve.state not in {CveState.PUBLISH_PENDING, CveState.PUBLISHED}:
        raise ValueError(f"cve is not in a publishable state for {cve_id}: {cve.state.value}")

    ai_review = _get_latest_ai_review(session, cve.id)
    policy_snapshot = decision.policy_snapshot
    reference_links = _get_cve_org_reference_links(session, cve.id)
    description_brief_metadata = _resolve_initial_description_brief_metadata(
        session,
        cve=cve,
        classification=classification,
        target_name=target_name,
        description_compressor=description_compressor,
    )
    content = build_initial_publish_content(
        cve=cve,
        classification=classification,
        decision=decision,
        ai_review=ai_review,
        reference_links=reference_links,
    )
    x_post_context = (
        _build_initial_x_post_context(
            session,
            cve=cve,
            classification=classification,
            description_brief_metadata=description_brief_metadata,
            reference_links=reference_links,
        )
        if target_name == "x"
        else None
    )
    content_hash = _compute_initial_publication_content_hash(
        content=content,
        x_post_context=x_post_context,
    )
    idempotency_key = fingerprint_payload(
        {
            "cve_id": cve.cve_id,
            "event_type": PublicationEventType.INITIAL.value,
            "target_name": target_name,
            "content_hash": content_hash,
        }
    )
    return PreparedPublication(
        cve=cve,
        classification=classification,
        decision=decision,
        policy_snapshot=policy_snapshot,
        ai_review=ai_review,
        target_name=target_name,
        event_type=PublicationEventType.INITIAL,
        content=content,
        content_hash=content_hash,
        idempotency_key=idempotency_key,
        payload_snapshot=_build_initial_publication_payload_snapshot(
            cve=cve,
            classification=classification,
            decision=decision,
            policy_snapshot=policy_snapshot,
            ai_review=ai_review,
            target_name=target_name,
            content=content,
            content_hash=content_hash,
            idempotency_key=idempotency_key,
            description_brief_metadata=description_brief_metadata,
            reference_links=reference_links,
            x_post_context=x_post_context,
        ),
    )


def prepare_update_publication(
    session: Session,
    cve_id: str,
    *,
    target_name: str,
) -> PreparedUpdatePublication:
    cve = _get_cve_by_public_id(session, cve_id)
    if cve.state not in {CveState.UPDATE_PENDING, CveState.PUBLISHED}:
        raise ValueError(f"cve is not in an update-publishable state for {cve_id}: {cve.state.value}")

    update_candidate = _get_latest_update_candidate(session, cve.id)
    if update_candidate is None:
        raise ValueError(f"no update candidate found for {cve_id}")
    if update_candidate.publication_event_id is None:
        raise ValueError(f"update candidate has no baseline publication event for {cve_id}")

    baseline_publication_event = _get_publication_event_by_id(session, update_candidate.publication_event_id)
    if baseline_publication_event is None:
        raise ValueError(f"baseline publication event not found for {cve_id}")

    classification = _get_latest_classification(session, cve.id)
    decision = baseline_publication_event.decision or _get_latest_policy_decision(session, cve.id)
    policy_snapshot = baseline_publication_event.policy_snapshot
    if policy_snapshot is None and decision is not None:
        policy_snapshot = decision.policy_snapshot
    ai_review = _get_latest_ai_review(session, cve.id)
    reference_links = _get_cve_org_reference_links(session, cve.id)
    content = build_update_publish_content(update_candidate=update_candidate, reference_links=reference_links)
    content_hash = fingerprint_payload(content.as_payload())
    idempotency_key = fingerprint_payload(
        {
            "cve_id": cve.cve_id,
            "event_type": PublicationEventType.UPDATE.value,
            "target_name": target_name,
            "comparison_fingerprint": update_candidate.comparison_fingerprint,
            "content_hash": content_hash,
        }
    )
    return PreparedPublication(
        cve=cve,
        classification=classification,
        decision=decision,
        policy_snapshot=policy_snapshot,
        ai_review=ai_review,
        target_name=target_name,
        event_type=PublicationEventType.UPDATE,
        content=content,
        content_hash=content_hash,
        idempotency_key=idempotency_key,
        payload_snapshot=_build_update_publication_payload_snapshot(
            session=session,
            cve=cve,
            classification=classification,
            decision=decision,
            policy_snapshot=policy_snapshot,
            ai_review=ai_review,
            update_candidate=update_candidate,
            baseline_publication_event=baseline_publication_event,
            target_name=target_name,
            content=content,
            content_hash=content_hash,
            idempotency_key=idempotency_key,
            reference_links=reference_links,
        ),
        update_candidate=update_candidate,
        baseline_publication_event=baseline_publication_event,
    )


def publish_publication(
    session: Session,
    cve_id: str,
    target: PublishTarget,
    *,
    attempted_at: datetime | None = None,
    actor_type: AuditActorType = AuditActorType.WORKER,
    description_compressor: DescriptionCompressor | None = None,
) -> PublicationResult:
    prepared = prepare_publication(
        session,
        cve_id,
        target_name=target.name,
        description_compressor=description_compressor,
    )
    return _publish_prepared(
        session,
        prepared,
        target,
        attempted_at=attempted_at,
        actor_type=actor_type,
    )


def publish_initial_publication(
    session: Session,
    cve_id: str,
    target: PublishTarget,
    *,
    attempted_at: datetime | None = None,
    actor_type: AuditActorType = AuditActorType.WORKER,
    description_compressor: DescriptionCompressor | None = None,
) -> PublicationResult:
    prepared = prepare_initial_publication(
        session,
        cve_id,
        target_name=target.name,
        description_compressor=description_compressor,
    )
    return _publish_prepared(
        session,
        prepared,
        target,
        attempted_at=attempted_at,
        actor_type=actor_type,
    )


def publish_update_publication(
    session: Session,
    cve_id: str,
    target: PublishTarget,
    *,
    attempted_at: datetime | None = None,
    actor_type: AuditActorType = AuditActorType.WORKER,
) -> PublicationResult:
    prepared = prepare_update_publication(session, cve_id, target_name=target.name)
    return _publish_prepared(
        session,
        prepared,
        target,
        attempted_at=attempted_at,
        actor_type=actor_type,
    )


def _publish_prepared(
    session: Session,
    prepared: PreparedPublication,
    target: PublishTarget,
    *,
    attempted_at: datetime | None,
    actor_type: AuditActorType,
) -> PublicationResult:
    effective_attempted_at = _normalize_datetime(attempted_at) or datetime.now(UTC)

    successful_duplicate = _get_successful_publication_event(
        session,
        cve_id=prepared.cve.id,
        event_type=prepared.event_type,
        target_name=prepared.target_name,
        content_hash=prepared.content_hash,
    )
    if successful_duplicate is not None:
        state_before = prepared.cve.state
        prepared.cve.state = _resolve_state(prepared.cve.state, CveState.PUBLISHED)
        session.flush()
        _write_audit_event(
            session,
            cve=prepared.cve,
            entity_id=successful_duplicate.id,
            actor_type=actor_type,
            event_type="publication.duplicate_blocked",
            state_before=state_before,
            state_after=prepared.cve.state,
            details=_publication_audit_details(
                prepared=prepared,
                details={
                    "existing_event_id": str(successful_duplicate.id),
                    "duplicate_reason": "existing_successful_publication",
                },
            ),
        )
        _record_update_publication_metric(
            session,
            prepared=prepared,
            result="duplicate_blocked",
            observed_at=effective_attempted_at,
            details={
                "cve_id": prepared.cve.cve_id,
                "publication_event_id": successful_duplicate.id,
                "existing_event_id": successful_duplicate.id,
            },
        )
        from cve_service.services.alerting import evaluate_operational_alerts

        evaluate_operational_alerts(
            session,
            evaluated_at=effective_attempted_at,
            trigger="publication.duplicate_blocked",
        )
        session.flush()
        return PublicationResult(
            cve_id=prepared.cve.cve_id,
            state=prepared.cve.state,
            decision_id=prepared.decision.id if prepared.decision is not None else None,
            event_id=successful_duplicate.id,
            event_type=prepared.event_type,
            event_status=successful_duplicate.status,
            target_name=prepared.target_name,
            content_hash=prepared.content_hash,
            idempotency_key=successful_duplicate.idempotency_key,
            published=True,
            duplicate_blocked=True,
            retry_blocked=False,
            reused_event=True,
            attempt_count=successful_duplicate.attempt_count,
            external_id=successful_duplicate.external_id,
            failure_category=None,
            retryable=False,
            requires_reconciliation=False,
            rate_limited=False,
        )

    event = _get_publication_event_by_idempotency(session, prepared.idempotency_key)
    reused_event = event is not None
    if event is None:
        event = PublicationEvent(
            cve_id=prepared.cve.id,
            decision_id=prepared.decision.id if prepared.decision is not None else None,
            policy_snapshot_id=prepared.policy_snapshot.id if prepared.policy_snapshot is not None else None,
            event_type=prepared.event_type,
            status=PublicationEventStatus.PENDING,
            destination=prepared.target_name,
            idempotency_key=prepared.idempotency_key,
            content_hash=prepared.content_hash,
            payload_snapshot=prepared.payload_snapshot,
            target_response={},
            attempt_count=0,
            occurred_at=effective_attempted_at,
            triggering_update_candidate_id=prepared.update_candidate.id if prepared.update_candidate is not None else None,
            baseline_publication_event_id=(
                prepared.baseline_publication_event.id if prepared.baseline_publication_event is not None else None
            ),
        )
        session.add(event)
        session.flush()
    elif bool((event.target_response or {}).get("retry_blocked")):
        _write_audit_event(
            session,
            cve=prepared.cve,
            entity_id=event.id,
            actor_type=actor_type,
            event_type="publication.retry_blocked",
            state_before=prepared.cve.state,
            state_after=prepared.cve.state,
            details=_publication_audit_details(
                prepared=prepared,
                details={
                    "attempt_count": event.attempt_count,
                    "external_id": event.external_id,
                    "failure_category": event.target_response.get("failure_category"),
                    "reused_event": reused_event,
                },
            ),
        )
        _record_target_publication_metric(
            session,
            prepared=prepared,
            result="retry_blocked",
            observed_at=effective_attempted_at,
            event=event,
            details={
                "cve_id": prepared.cve.cve_id,
                "publication_event_id": event.id,
                "attempt_count": event.attempt_count,
                "external_id": event.external_id,
            },
        )
        from cve_service.services.alerting import evaluate_operational_alerts

        evaluate_operational_alerts(
            session,
            evaluated_at=effective_attempted_at,
            trigger="publication.retry_blocked",
        )
        session.flush()
        return PublicationResult(
            cve_id=prepared.cve.cve_id,
            state=prepared.cve.state,
            decision_id=prepared.decision.id if prepared.decision is not None else None,
            event_id=event.id,
            event_type=prepared.event_type,
            event_status=event.status,
            target_name=prepared.target_name,
            content_hash=prepared.content_hash,
            idempotency_key=prepared.idempotency_key,
            published=False,
            duplicate_blocked=False,
            retry_blocked=True,
            reused_event=reused_event,
            attempt_count=event.attempt_count,
            external_id=event.external_id,
            failure_category=event.target_response.get("failure_category"),
            retryable=bool(event.target_response.get("retryable")),
            requires_reconciliation=bool(event.target_response.get("requires_reconciliation")),
            rate_limited=bool(event.target_response.get("rate_limited")),
        )

    attempt_number = event.attempt_count + 1
    request = PublishRequest(
        cve_id=prepared.cve.cve_id,
        event_type=prepared.event_type.value,
        target_name=prepared.target_name,
        idempotency_key=prepared.idempotency_key,
        content_hash=prepared.content_hash,
        content=prepared.content,
        payload_snapshot=prepared.payload_snapshot,
    )

    try:
        response = target.publish(request)
    except PublishTargetError as exc:
        event.status = PublicationEventStatus.FAILED
        event.attempt_count = attempt_number
        event.last_attempted_at = effective_attempted_at
        event.last_error = str(exc)
        event.external_id = exc.external_id or event.external_id
        event.target_response = exc.as_payload(target_name=prepared.target_name)
        event.payload_snapshot = _with_attempt_record(
            event.payload_snapshot,
            attempt_number=attempt_number,
            attempted_at=effective_attempted_at,
            outcome=PublicationEventStatus.FAILED,
            external_id=event.external_id,
            response_payload=event.target_response,
            error=str(exc),
        )
        session.flush()

        _write_audit_event(
            session,
            cve=prepared.cve,
            entity_id=event.id,
            actor_type=actor_type,
            event_type="publication.failed",
            state_before=prepared.cve.state,
            state_after=prepared.cve.state,
            details=_publication_audit_details(
                prepared=prepared,
                details={
                    "attempt_count": event.attempt_count,
                    "error": str(exc),
                    "external_id": event.external_id,
                    "failure_category": exc.category,
                    "retryable": exc.retryable,
                    "requires_reconciliation": exc.requires_reconciliation,
                    "rate_limited": exc.rate_limited,
                    "reused_event": reused_event,
                },
            ),
        )
        _record_update_publication_metric(
            session,
            prepared=prepared,
            result="failed",
            observed_at=effective_attempted_at,
            details={
                "cve_id": prepared.cve.cve_id,
                "publication_event_id": event.id,
                "attempt_count": event.attempt_count,
                "error": str(exc),
            },
        )
        _record_target_publication_metric(
            session,
            prepared=prepared,
            result=exc.category,
            observed_at=effective_attempted_at,
            event=event,
            details={
                "cve_id": prepared.cve.cve_id,
                "publication_event_id": event.id,
                "attempt_count": event.attempt_count,
                "error": str(exc),
                "external_id": event.external_id,
            },
        )
        from cve_service.services.alerting import evaluate_operational_alerts

        evaluate_operational_alerts(
            session,
            evaluated_at=effective_attempted_at,
            trigger="publication.failed",
        )
        session.flush()
        return PublicationResult(
            cve_id=prepared.cve.cve_id,
            state=prepared.cve.state,
            decision_id=prepared.decision.id if prepared.decision is not None else None,
            event_id=event.id,
            event_type=prepared.event_type,
            event_status=event.status,
            target_name=prepared.target_name,
            content_hash=prepared.content_hash,
            idempotency_key=prepared.idempotency_key,
            published=False,
            duplicate_blocked=False,
            retry_blocked=False,
            reused_event=reused_event,
            attempt_count=event.attempt_count,
            external_id=event.external_id,
            failure_category=exc.category,
            retryable=exc.retryable,
            requires_reconciliation=exc.requires_reconciliation,
            rate_limited=exc.rate_limited,
        )
    except Exception as exc:
        event.status = PublicationEventStatus.FAILED
        event.attempt_count = attempt_number
        event.last_attempted_at = effective_attempted_at
        event.last_error = str(exc)
        event.target_response = {
            "target": prepared.target_name,
            "error": str(exc),
            "failure_category": "unclassified_failure",
            "retryable": False,
            "requires_reconciliation": False,
            "retry_blocked": False,
            "rate_limited": False,
        }
        event.payload_snapshot = _with_attempt_record(
            event.payload_snapshot,
            attempt_number=attempt_number,
            attempted_at=effective_attempted_at,
            outcome=PublicationEventStatus.FAILED,
            external_id=event.external_id,
            response_payload=event.target_response,
            error=str(exc),
        )
        session.flush()

        _write_audit_event(
            session,
            cve=prepared.cve,
            entity_id=event.id,
            actor_type=actor_type,
            event_type="publication.failed",
            state_before=prepared.cve.state,
            state_after=prepared.cve.state,
            details=_publication_audit_details(
                prepared=prepared,
                details={
                    "attempt_count": event.attempt_count,
                    "error": str(exc),
                    "failure_category": "unclassified_failure",
                    "reused_event": reused_event,
                },
            ),
        )
        _record_update_publication_metric(
            session,
            prepared=prepared,
            result="failed",
            observed_at=effective_attempted_at,
            details={
                "cve_id": prepared.cve.cve_id,
                "publication_event_id": event.id,
                "attempt_count": event.attempt_count,
                "error": str(exc),
            },
        )
        _record_target_publication_metric(
            session,
            prepared=prepared,
            result="unclassified_failure",
            observed_at=effective_attempted_at,
            event=event,
            details={
                "cve_id": prepared.cve.cve_id,
                "publication_event_id": event.id,
                "attempt_count": event.attempt_count,
                "error": str(exc),
            },
        )
        from cve_service.services.alerting import evaluate_operational_alerts

        evaluate_operational_alerts(
            session,
            evaluated_at=effective_attempted_at,
            trigger="publication.failed",
        )
        session.flush()
        return PublicationResult(
            cve_id=prepared.cve.cve_id,
            state=prepared.cve.state,
            decision_id=prepared.decision.id if prepared.decision is not None else None,
            event_id=event.id,
            event_type=prepared.event_type,
            event_status=event.status,
            target_name=prepared.target_name,
            content_hash=prepared.content_hash,
            idempotency_key=prepared.idempotency_key,
            published=False,
            duplicate_blocked=False,
            retry_blocked=False,
            reused_event=reused_event,
            attempt_count=event.attempt_count,
            external_id=event.external_id,
            failure_category="unclassified_failure",
            retryable=False,
            requires_reconciliation=False,
            rate_limited=False,
        )

    state_before = prepared.cve.state
    prepared.cve.state = _resolve_state(prepared.cve.state, CveState.PUBLISHED)
    event.status = PublicationEventStatus.PUBLISHED
    event.external_id = response.external_id
    event.target_response = dict(response.response_payload)
    event.attempt_count = attempt_number
    event.last_attempted_at = effective_attempted_at
    event.published_at = _normalize_datetime(response.published_at) or effective_attempted_at
    event.last_error = None
    event.occurred_at = event.published_at
    event.payload_snapshot = _with_attempt_record(
        event.payload_snapshot,
        attempt_number=attempt_number,
        attempted_at=effective_attempted_at,
        outcome=PublicationEventStatus.PUBLISHED,
        external_id=response.external_id,
        response_payload=response.response_payload,
        error=None,
    )
    session.flush()

    _write_audit_event(
        session,
        cve=prepared.cve,
        entity_id=event.id,
        actor_type=actor_type,
        event_type="publication.succeeded",
        state_before=state_before,
        state_after=prepared.cve.state,
        details=_publication_audit_details(
            prepared=prepared,
            details={
                "attempt_count": event.attempt_count,
                "external_id": event.external_id,
                "reused_event": reused_event,
            },
        ),
    )
    _record_update_publication_metric(
        session,
        prepared=prepared,
        result="succeeded",
        observed_at=event.published_at,
        details={
            "cve_id": prepared.cve.cve_id,
            "publication_event_id": event.id,
            "attempt_count": event.attempt_count,
            "external_id": event.external_id,
        },
    )
    _record_target_publication_metric(
        session,
        prepared=prepared,
        result="succeeded",
        observed_at=event.published_at,
        event=event,
        details={
            "cve_id": prepared.cve.cve_id,
            "publication_event_id": event.id,
            "attempt_count": event.attempt_count,
            "external_id": event.external_id,
        },
    )
    from cve_service.services.alerting import evaluate_operational_alerts

    evaluate_operational_alerts(
        session,
        evaluated_at=event.published_at,
        trigger="publication.succeeded",
    )
    session.flush()
    return PublicationResult(
        cve_id=prepared.cve.cve_id,
        state=prepared.cve.state,
        decision_id=prepared.decision.id if prepared.decision is not None else None,
        event_id=event.id,
        event_type=prepared.event_type,
        event_status=event.status,
        target_name=prepared.target_name,
        content_hash=prepared.content_hash,
        idempotency_key=prepared.idempotency_key,
        published=True,
        duplicate_blocked=False,
        retry_blocked=False,
        reused_event=reused_event,
        attempt_count=event.attempt_count,
        external_id=event.external_id,
        failure_category=None,
        retryable=False,
        requires_reconciliation=False,
        rate_limited=False,
    )


def _build_initial_publication_payload_snapshot(
    *,
    cve: CVE,
    classification: Classification,
    decision: PolicyDecision,
    policy_snapshot: PolicyConfigurationSnapshot | None,
    ai_review: AIReview | None,
    target_name: str,
    content: PublishContent,
    content_hash: str,
    idempotency_key: str,
    description_brief_metadata: dict[str, Any],
    reference_links: dict[str, Any],
    x_post_context: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": PUBLICATION_EVENT_SCHEMA_VERSION,
        "event_type": PublicationEventType.INITIAL.value,
        "target": {
            "name": target_name,
            "idempotency_key": idempotency_key,
        },
        "publish_content": content.as_payload(),
        "replay_context": {
            "cve": {
                "cve_id": cve.cve_id,
                "title": cve.title,
                "description": cve.description,
                "severity": cve.severity,
                "source_published_at": _serialize_datetime(cve.source_published_at),
                "source_modified_at": _serialize_datetime(cve.source_modified_at),
                "state": cve.state.value,
            },
            "classification": _serialize_classification(classification),
            "policy_decision": _serialize_policy_decision(decision),
            "policy_configuration": _serialize_policy_configuration(policy_snapshot, decision),
            "ai_review": _serialize_ai_review(ai_review),
            "description_compression": {
                "description_brief": description_brief_metadata.get("description_brief"),
                "source": description_brief_metadata.get("description_brief_source"),
                "model_name": description_brief_metadata.get("description_brief_model_name"),
                "prompt_version": description_brief_metadata.get("description_brief_prompt_version"),
            },
            "x_post": x_post_context,
            "source_references": {
                "origin": "cve.org",
                "links": reference_links,
            },
        },
        "content_hash": content_hash,
        "attempts": [],
    }


def _resolve_initial_description_brief_metadata(
    session: Session,
    *,
    cve: CVE,
    classification: Classification,
    target_name: str,
    description_compressor: DescriptionCompressor | None,
) -> dict[str, Any]:
    existing_metadata = _get_existing_initial_publish_metadata(session, cve.id, target_name=target_name)
    if existing_metadata.get("description_brief"):
        return {
            "description_brief": existing_metadata.get("description_brief"),
            "description_brief_source": existing_metadata.get("description_brief_source"),
            "description_brief_model_name": existing_metadata.get("description_brief_model_name"),
            "description_brief_prompt_version": existing_metadata.get("description_brief_prompt_version"),
        }

    if description_compressor is None:
        return {
            "description_brief": fallback_description_brief(
                cve.description,
                canonical_product_name=classification.details.get("canonical_product_name"),
            ),
            "description_brief_source": "fallback",
            "description_brief_model_name": None,
            "description_brief_prompt_version": None,
        }

    try:
        result = description_compressor.compress(
            DescriptionCompressionRequest(
                cve_id=cve.cve_id,
                title=cve.title,
                description=cve.description,
                severity=cve.severity,
                canonical_name=classification.details.get("canonical_name"),
                canonical_vendor_name=classification.details.get("canonical_vendor_name"),
                canonical_product_name=classification.details.get("canonical_product_name"),
            )
        )
    except Exception:
        return {
            "description_brief": fallback_description_brief(
                cve.description,
                canonical_product_name=classification.details.get("canonical_product_name"),
            ),
            "description_brief_source": "fallback",
            "description_brief_model_name": None,
            "description_brief_prompt_version": None,
        }

    return {
        "description_brief": result.compressed_description,
        "description_brief_source": result.source,
        "description_brief_model_name": result.model_name,
        "description_brief_prompt_version": result.prompt_version,
    }


def _compute_initial_publication_content_hash(
    *,
    content: PublishContent,
    x_post_context: dict[str, Any] | None,
) -> str:
    if not x_post_context:
        return fingerprint_payload(content.as_payload())
    return fingerprint_payload(
        {
            "publish_content": content.as_payload(),
            "x_post": x_post_context,
        }
    )


def _build_initial_x_post_context(
    session: Session,
    *,
    cve: CVE,
    classification: Classification,
    description_brief_metadata: dict[str, Any],
    reference_links: dict[str, Any],
) -> dict[str, Any]:
    snapshot = _get_latest_ingestion_snapshot(session, cve.id)
    raw_payload = snapshot.raw_payload if snapshot is not None else {}
    canonical_vendor_name = classification.details.get("canonical_vendor_name")
    canonical_product_name = classification.details.get("canonical_product_name")
    public_poc = (
        "Yes" if _reference_category_has_urls(reference_links, "poc") else _render_initial_binary_status(cve.poc_status.value)
    )
    affected_product = _extract_x_affected_product(
        raw_payload,
        canonical_vendor_name=canonical_vendor_name,
        canonical_product_name=canonical_product_name,
    )
    x_post_context = {
        "primary_product": affected_product or _format_product_name(canonical_vendor_name, canonical_product_name),
        "vulnerability_type": _derive_vulnerability_type(cve.title, cve.description),
        "description": description_brief_metadata.get("description_brief") or "No description provided.",
        "severity": _humanize_severity(cve.severity),
        "exploitation": _render_initial_exploitation_status(cve.itw_status.value),
        "public_poc": public_poc,
        "patch_available": _extract_patch_availability(
            raw_payload,
            reference_links=reference_links,
            source_description=cve.description,
        ),
        "affected_product": affected_product or "Unknown",
        "affected_version": _extract_x_affected_version(
            raw_payload,
            canonical_product_name=canonical_product_name,
        )
        or "Unknown",
        "mitigations": _extract_source_backed_mitigations(raw_payload),
    }
    return _refine_initial_x_post_context(
        x_post_context,
        raw_payload=raw_payload,
        title=cve.title,
        description=cve.description,
        reference_links=reference_links,
    )


def _reference_category_has_urls(reference_links: dict[str, Any], category: str) -> bool:
    values = reference_links.get(category)
    if not isinstance(values, list):
        return False

    for item in values:
        if isinstance(item, dict):
            url = item.get("url")
        else:
            url = item
        if isinstance(url, str) and url:
            return True
    return False


def _derive_vulnerability_type(title: str | None, description: str | None) -> str:
    return _derive_vulnerability_type_from_texts(title, description)


def _derive_vulnerability_type_from_texts(*texts: Any) -> str:
    haystack = " ".join(str(text).strip() for text in texts if isinstance(text, str) and text.strip()).lower()
    vulnerability_types = (
        (r"\bdefault password\b|\buse of default password\b|\bunchanged (?:high-privileged )?(?:default|initial) password\b", "Default Credentials"),
        (r"\bldap injection\b", "LDAP Injection"),
        (r"\bremote code execution\b|\brace\b", "Remote Code Execution"),
        (r"\bprivilege escalation\b|\beop\b", "Privilege Escalation"),
        (r"\bdenial of service\b|\bdos\b", "Denial of Service"),
        (r"\bsql injection\b", "SQL Injection"),
        (r"\bcommand injection\b", "Command Injection"),
        (r"\bpath traversal\b|\bdirectory traversal\b", "Path Traversal"),
        (r"\bauthentication bypass\b|\bauth bypass\b", "Authentication Bypass"),
        (r"\bserver-side request forgery\b|\bssrf\b", "Server-Side Request Forgery"),
        (r"\bxml external entity\b|\bxxe\b", "XML External Entity Injection"),
        (r"\bdeserialization\b", "Deserialization"),
        (r"\bcross-site scripting\b|\bxss\b", "Cross-Site Scripting"),
        (r"\bcross-site request forgery\b|\bcsrf\b", "Cross-Site Request Forgery"),
        (r"\binformation disclosure\b", "Information Disclosure"),
        (r"\barbitrary file upload\b", "Arbitrary File Upload"),
        (r"\barbitrary file deletion\b", "Arbitrary File Deletion"),
        (r"\bopen redirect\b", "Open Redirect"),
        (r"\buse-after-free\b", "Use-After-Free"),
        (r"\bbuffer overflow\b", "Buffer Overflow"),
        (r"\bmemory corruption\b", "Memory Corruption"),
    )
    for pattern, label in vulnerability_types:
        if re.search(pattern, haystack):
            return label
    return "Vulnerability"


def _humanize_severity(severity: str | None) -> str:
    if not isinstance(severity, str) or not severity.strip():
        return "Unknown"
    return severity.strip().lower().capitalize()


def _render_initial_exploitation_status(status: str | None) -> str:
    normalized = str(status or "").strip().upper()
    if normalized == "PRESENT":
        return "Confirmed in the wild"
    if normalized == "ABSENT":
        return "No confirmed in-the-wild exploitation"
    return "Unknown"


def _render_initial_binary_status(status: str | None) -> str:
    normalized = str(status or "").strip().upper()
    if normalized == "PRESENT":
        return "Yes"
    if normalized == "ABSENT":
        return "No"
    return "Unknown"


def _extract_x_affected_product(
    raw_payload: Any,
    *,
    canonical_vendor_name: str | None,
    canonical_product_name: str | None,
) -> str | None:
    affected_entries = _iter_cve_org_affected_entries(raw_payload)
    if not affected_entries:
        return _format_product_name(canonical_vendor_name, canonical_product_name) or None

    preferred_entry = _select_preferred_affected_entry(
        affected_entries,
        canonical_product_name=canonical_product_name,
    )
    if preferred_entry is None:
        return _format_product_name(canonical_vendor_name, canonical_product_name) or None
    return _format_product_name(preferred_entry.get("vendor"), preferred_entry.get("product")) or None


def _extract_x_affected_version(raw_payload: Any, *, canonical_product_name: str | None) -> str | None:
    affected_entries = _iter_cve_org_affected_entries(raw_payload)
    if not affected_entries:
        return None

    preferred_entry = _select_preferred_affected_entry(
        affected_entries,
        canonical_product_name=canonical_product_name,
    )
    candidate_entries = [preferred_entry] if preferred_entry is not None else []
    candidate_entries.extend(entry for entry in affected_entries if entry is not preferred_entry)
    for entry in candidate_entries:
        formatted_versions = _format_affected_versions(entry)
        if formatted_versions:
            return "; ".join(formatted_versions)
    return None


def _extract_patch_availability(
    raw_payload: Any,
    *,
    reference_links: dict[str, Any],
    source_description: str | None = None,
) -> str:
    for reference in _iter_cve_org_reference_entries(raw_payload):
        tags = {str(tag).strip().lower() for tag in reference.get("tags") or ()}
        if {"patch", "release-notes"} & tags:
            return "Yes"

    guidance_texts = list(_iter_source_guidance_texts(raw_payload))
    if isinstance(source_description, str) and source_description.strip():
        guidance_texts.insert(0, source_description.strip())

    for text in guidance_texts:
        lowered = text.lower()
        if any(marker in lowered for marker in ("no fix", "no patch", "no workaround", "not currently available")):
            return "No"
        if any(
            marker in lowered
            for marker in ("apply the patch", "apply patches", "security update", "fixed in", "upgrade to", "update to", "hotfix")
        ):
            return "Yes"

    if _has_versioned_fix_boundary(raw_payload):
        return "Yes"

    if isinstance(reference_links, dict) and reference_links.get("vendor"):
        return "Unknown"
    return "Unknown"


def _refine_initial_x_post_context(
    x_post_context: dict[str, Any],
    *,
    raw_payload: Any,
    title: str | None,
    description: str | None,
    reference_links: dict[str, Any],
) -> dict[str, Any]:
    refined = dict(x_post_context)
    secondary_texts = [
        title,
        description,
        *_iter_source_guidance_texts(raw_payload),
        *_iter_reference_hint_texts(reference_links),
    ]

    if str(refined.get("vulnerability_type") or "").strip() in {"", "Vulnerability"}:
        refined["vulnerability_type"] = _derive_vulnerability_type_from_texts(*secondary_texts)

    if str(refined.get("patch_available") or "").strip() in {"", "Unknown"}:
        refined["patch_available"] = _extract_patch_availability(
            raw_payload,
            reference_links=reference_links,
            source_description=description,
        )

    return refined


def _iter_reference_hint_texts(reference_links: dict[str, Any]) -> list[str]:
    if not isinstance(reference_links, dict):
        return []

    values: list[str] = []
    for items in reference_links.values():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                for key in ("name", "url"):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        values.append(value.strip())
    return values


def _has_versioned_fix_boundary(raw_payload: Any) -> bool:
    for entry in _iter_cve_org_affected_entries(raw_payload):
        for formatted in _format_affected_versions(entry):
            if " < " in formatted or formatted.startswith("< ") or " <= " in formatted or formatted.startswith("<= "):
                return True
    return False


def _extract_source_backed_mitigations(raw_payload: Any) -> list[str]:
    mitigations: list[str] = []
    seen: set[str] = set()
    for source_key, text in _iter_source_guidance_items(raw_payload):
        normalized = " ".join(text.split())
        if not normalized:
            continue
        lowered = normalized.lower()
        if _looks_like_patch_guidance(lowered):
            continue
        if source_key == "solutions" and not _looks_like_mitigation_guidance(lowered):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        mitigations.append(normalized)
        if len(mitigations) >= 3:
            break
    return mitigations


def _iter_cve_org_affected_entries(raw_payload: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_payload, dict):
        return []
    containers = raw_payload.get("containers")
    if not isinstance(containers, dict):
        return []

    affected_entries: list[dict[str, Any]] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        affected_entries.extend(_coerce_affected_entries(cna.get("affected")))

    adp_entries = containers.get("adp")
    if isinstance(adp_entries, list):
        for adp in adp_entries:
            if isinstance(adp, dict):
                affected_entries.extend(_coerce_affected_entries(adp.get("affected")))
    return affected_entries


def _coerce_affected_entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    affected_entries: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        affected_entries.append(
            {
                "vendor": item.get("vendor"),
                "product": item.get("product"),
                "default_status": item.get("defaultStatus"),
                "versions": list(item.get("versions") or ()) if isinstance(item.get("versions"), list) else [],
            }
        )
    return affected_entries


def _select_preferred_affected_entry(
    entries: list[dict[str, Any]],
    *,
    canonical_product_name: str | None,
) -> dict[str, Any] | None:
    if not entries:
        return None
    normalized_canonical = _normalize_product_token(canonical_product_name)
    if normalized_canonical:
        for entry in entries:
            if _normalize_product_token(entry.get("product")) == normalized_canonical:
                return entry
    return entries[0]


def _format_affected_versions(entry: dict[str, Any]) -> list[str]:
    default_status = str(entry.get("default_status") or "").strip().lower()
    formatted_versions: list[str] = []
    seen: set[str] = set()
    for version in entry.get("versions") or ():
        if not isinstance(version, dict):
            continue
        formatted = _format_single_affected_version(version, default_status=default_status)
        if formatted and formatted not in seen:
            seen.add(formatted)
            formatted_versions.append(formatted)
    return formatted_versions


def _format_single_affected_version(version: dict[str, Any], *, default_status: str) -> str | None:
    status = str(version.get("status") or default_status or "").strip().lower()
    if status and status != "affected":
        return None

    version_value = str(version.get("version") or "").strip()
    less_than = str(version.get("lessThan") or "").strip()
    less_than_or_equal = str(version.get("lessThanOrEqual") or "").strip()
    changes = version.get("changes")

    if less_than:
        if version_value and version_value not in {"*", "n/a", "unspecified"}:
            return f">= {version_value} and < {less_than}"
        return f"< {less_than}"
    if less_than_or_equal:
        if version_value and version_value not in {"*", "n/a", "unspecified"}:
            return f">= {version_value} and <= {less_than_or_equal}"
        return f"<= {less_than_or_equal}"
    if version_value and version_value not in {"*", "n/a", "unspecified"}:
        return version_value
    if isinstance(changes, list):
        for change in changes:
            if not isinstance(change, dict):
                continue
            at_version = str(change.get("at") or "").strip()
            change_status = str(change.get("status") or "").strip().lower()
            if at_version and change_status == "unaffected":
                return f"< {at_version}"
    return None


def _iter_source_guidance_items(raw_payload: Any) -> list[tuple[str, str]]:
    if not isinstance(raw_payload, dict):
        return []
    containers = raw_payload.get("containers")
    if not isinstance(containers, dict):
        return []

    guidance_items: list[tuple[str, str]] = []
    for container in _iter_guidance_containers(containers):
        for key in ("mitigations", "workarounds", "solutions"):
            entries = container.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                text = _extract_english_text(entry)
                if text:
                    guidance_items.append((key, text))
    return guidance_items


def _iter_source_guidance_texts(raw_payload: Any) -> list[str]:
    return [text for _, text in _iter_source_guidance_items(raw_payload)]


def _iter_guidance_containers(containers: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        values.append(cna)
    adp_entries = containers.get("adp")
    if isinstance(adp_entries, list):
        values.extend(entry for entry in adp_entries if isinstance(entry, dict))
    return values


def _extract_english_text(entry: dict[str, Any]) -> str | None:
    language = str(entry.get("lang") or "").strip().lower().replace("_", "-")
    if language and language != "en" and not language.startswith("en-"):
        return None
    for key in ("value", "text", "description", "details"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _looks_like_patch_guidance(text: str) -> bool:
    return any(
        marker in text
        for marker in ("apply the patch", "apply patches", "patch now", "update to", "upgrade to", "fixed in", "security update", "install the update")
    )


def _looks_like_mitigation_guidance(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "restrict",
            "disable",
            "block",
            "filter",
            "limit access",
            "workaround",
            "mitigat",
            "temporary",
            "configuration",
            "firewall",
            "segmentation",
            "network access",
        )
    )


def _format_product_name(vendor_name: Any, product_name: Any) -> str:
    vendor = str(vendor_name or "").strip()
    product = str(product_name or "").strip()
    if not vendor and not product:
        return "Unknown"
    if not vendor:
        return product
    if not product:
        return vendor
    if vendor.lower() in product.lower():
        return product
    return f"{vendor} {product}"


def _normalize_product_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _build_update_publication_payload_snapshot(
    *,
    session: Session,
    cve: CVE,
    classification: Classification | None,
    decision: PolicyDecision | None,
    policy_snapshot: PolicyConfigurationSnapshot | None,
    ai_review: AIReview | None,
    update_candidate: UpdateCandidate,
    baseline_publication_event: PublicationEvent,
    target_name: str,
    content: PublishContent,
    content_hash: str,
    idempotency_key: str,
    reference_links: dict[str, Any],
) -> dict[str, Any]:
    lineage_root = _resolve_lineage_root_publication_event(session, baseline_publication_event)
    return {
        "schema_version": UPDATE_PUBLICATION_EVENT_SCHEMA_VERSION,
        "event_type": PublicationEventType.UPDATE.value,
        "target": {
            "name": target_name,
            "idempotency_key": idempotency_key,
        },
        "publish_content": content.as_payload(),
        "replay_context": {
            "cve": {
                "cve_id": cve.cve_id,
                "title": cve.title,
                "description": cve.description,
                "severity": cve.severity,
                "source_published_at": _serialize_datetime(cve.source_published_at),
                "source_modified_at": _serialize_datetime(cve.source_modified_at),
                "state": cve.state.value,
            },
            "classification": _serialize_classification(classification),
            "policy_decision": _serialize_policy_decision(decision),
            "policy_configuration": _serialize_policy_configuration(policy_snapshot, decision),
            "ai_review": _serialize_ai_review(ai_review),
            "source_references": {
                "origin": "cve.org",
                "links": reference_links,
            },
            "update_candidate": {
                "id": str(update_candidate.id),
                "comparison_fingerprint": update_candidate.comparison_fingerprint,
                "comparator_version": update_candidate.comparator_version,
                "reason_codes": list(update_candidate.reason_codes),
                "comparison_snapshot": update_candidate.comparison_snapshot,
            },
            "publication_lineage": {
            "baseline_publication_event_id": str(baseline_publication_event.id),
            "baseline_event_type": baseline_publication_event.event_type.value,
            "lineage_root_publication_event_id": str(lineage_root.id) if lineage_root is not None else None,
        },
        "baseline_publication": {
                "id": str(baseline_publication_event.id),
                "event_type": baseline_publication_event.event_type.value,
                "decision_id": str(baseline_publication_event.decision_id)
                if baseline_publication_event.decision_id is not None
                else None,
                "policy_snapshot_id": str(baseline_publication_event.policy_snapshot_id)
                if baseline_publication_event.policy_snapshot_id is not None
                else None,
            "published_at": _serialize_datetime(baseline_publication_event.published_at),
            "content_hash": baseline_publication_event.content_hash,
            "destination": baseline_publication_event.destination,
            "external_id": baseline_publication_event.external_id,
            "target_response": baseline_publication_event.target_response,
        },
    },
    "content_hash": content_hash,
    "attempts": [],
}


def _publication_audit_details(
    *,
    prepared: PreparedPublication,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "event_type": prepared.event_type.value,
        "target_name": prepared.target_name,
        "content_hash": prepared.content_hash,
        "idempotency_key": prepared.idempotency_key,
        "triggering_update_candidate_id": str(prepared.update_candidate.id) if prepared.update_candidate is not None else None,
        "baseline_publication_event_id": (
            str(prepared.baseline_publication_event.id) if prepared.baseline_publication_event is not None else None
        ),
        **details,
    }


def _with_attempt_record(
    payload_snapshot: dict[str, Any],
    *,
    attempt_number: int,
    attempted_at: datetime,
    outcome: PublicationEventStatus,
    external_id: str | None,
    response_payload: dict[str, Any],
    error: str | None,
) -> dict[str, Any]:
    attempts = list(payload_snapshot.get("attempts", []))
    attempts.append(
        {
            "attempt_number": attempt_number,
            "attempted_at": _serialize_datetime(attempted_at),
            "outcome": outcome.value,
            "external_id": external_id,
            "response_payload": response_payload,
            "error": error,
        }
    )
    return {
        **payload_snapshot,
        "attempts": attempts,
    }


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown cve_id: {cve_id}")
    return cve


def _get_latest_classification(session: Session, cve_pk: UUID) -> Classification | None:
    return session.scalar(
        select(Classification)
        .where(Classification.cve_id == cve_pk)
        .order_by(Classification.created_at.desc(), Classification.id.desc())
        .limit(1)
    )


def _get_latest_ai_review(session: Session, cve_pk: UUID) -> AIReview | None:
    return session.scalar(
        select(AIReview)
        .where(AIReview.cve_id == cve_pk)
        .order_by(AIReview.created_at.desc(), AIReview.id.desc())
        .limit(1)
    )


def _get_latest_ingestion_snapshot(session: Session, cve_pk: UUID) -> CVEIngestionSnapshot | None:
    return session.scalar(
        select(CVEIngestionSnapshot)
        .where(CVEIngestionSnapshot.cve_id == cve_pk)
        .order_by(CVEIngestionSnapshot.snapshot_index.desc(), CVEIngestionSnapshot.id.desc())
        .limit(1)
    )


def _get_latest_policy_decision(session: Session, cve_pk: UUID) -> PolicyDecision | None:
    return session.scalar(
        select(PolicyDecision)
        .where(PolicyDecision.cve_id == cve_pk)
        .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
        .limit(1)
    )


def _get_latest_update_candidate(session: Session, cve_pk: UUID) -> UpdateCandidate | None:
    return session.scalar(
        select(UpdateCandidate)
        .where(UpdateCandidate.cve_id == cve_pk)
        .order_by(UpdateCandidate.created_at.desc(), UpdateCandidate.id.desc())
        .limit(1)
    )


def _get_publication_event_by_id(session: Session, event_id: UUID | None) -> PublicationEvent | None:
    if event_id is None:
        return None
    return session.scalar(select(PublicationEvent).where(PublicationEvent.id == event_id).limit(1))


def _get_existing_initial_publish_metadata(session: Session, cve_pk: UUID, *, target_name: str) -> dict[str, Any]:
    event = session.scalar(
        select(PublicationEvent)
        .where(
            PublicationEvent.cve_id == cve_pk,
            PublicationEvent.event_type == PublicationEventType.INITIAL,
            PublicationEvent.destination == target_name,
        )
        .order_by(PublicationEvent.created_at.desc(), PublicationEvent.id.desc())
        .limit(1)
    )
    if event is None:
        return {}
    payload_snapshot = event.payload_snapshot or {}
    publish_content = payload_snapshot.get("publish_content") or {}
    metadata = publish_content.get("metadata") or {}
    replay_context = payload_snapshot.get("replay_context") or {}
    description_compression = replay_context.get("description_compression") or {}
    merged = dict(metadata) if isinstance(metadata, dict) else {}
    if isinstance(description_compression, dict):
        merged.setdefault("description_brief", description_compression.get("description_brief"))
        merged.setdefault("description_brief_source", description_compression.get("source"))
        merged.setdefault("description_brief_model_name", description_compression.get("model_name"))
        merged.setdefault("description_brief_prompt_version", description_compression.get("prompt_version"))
    x_post = replay_context.get("x_post")
    if isinstance(x_post, dict):
        merged.setdefault("x_post", x_post)
    return merged


def _get_cve_org_reference_links(session: Session, cve_pk: UUID) -> dict[str, Any]:
    snapshot = _get_latest_ingestion_snapshot(session, cve_pk)
    if snapshot is None or snapshot.source_name != "cve.org":
        return {}
    return _extract_cve_org_reference_links(snapshot.raw_payload)


def _extract_cve_org_reference_links(raw_payload: Any) -> dict[str, Any]:
    if not isinstance(raw_payload, dict):
        return {}

    categorized: dict[str, list[dict[str, Any]]] = {
        "vendor": [],
        "research": [],
        "poc": [],
        "itw": [],
    }
    for index, reference in enumerate(_iter_cve_org_reference_entries(raw_payload)):
        url = reference.get("url")
        if not isinstance(url, str) or not url:
            continue
        category = _classify_cve_org_reference(reference)
        categorized[category].append(
            {
                "url": url,
                "name": reference.get("name"),
                "tags": list(reference.get("tags") or ()),
                "_index": index,
            }
        )

    result: dict[str, Any] = {}
    for category, entries in categorized.items():
        if not entries:
            continue
        selected = sorted(
            entries,
            key=lambda item: (-_reference_priority_score(item, category), item["_index"]),
        )[:MAX_REFERENCE_LINKS_PER_CATEGORY]
        result[category] = [
            {
                "url": item["url"],
                "name": item.get("name"),
                "tags": item.get("tags", []),
            }
            for item in sorted(selected, key=lambda item: item["_index"])
        ]
    return result


def _iter_cve_org_reference_entries(raw_payload: dict[str, Any]) -> list[dict[str, Any]]:
    containers = raw_payload.get("containers")
    if not isinstance(containers, dict):
        return []

    references: list[dict[str, Any]] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        references.extend(_coerce_reference_list(cna.get("references")))

    adp_entries = containers.get("adp")
    if isinstance(adp_entries, list):
        for adp in adp_entries:
            if isinstance(adp, dict):
                references.extend(_coerce_reference_list(adp.get("references")))
    return references


def _coerce_reference_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    references: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        tags = item.get("tags")
        references.append(
            {
                "url": item.get("url"),
                "name": item.get("name"),
                "tags": [str(tag).strip().lower() for tag in tags if isinstance(tag, str) and tag.strip()]
                if isinstance(tags, list)
                else [],
            }
        )
    return references


def _classify_cve_org_reference(reference: dict[str, Any]) -> str:
    url = str(reference.get("url") or "").lower()
    tags = {str(tag).strip().lower() for tag in reference.get("tags") or ()}

    if _looks_like_itw_reference(url):
        return "itw"
    if "exploit" in tags or _looks_like_poc_reference(url):
        return "poc"
    if {"vendor-advisory", "patch", "release-notes"} & tags:
        return "vendor"
    return "research"


def _reference_priority_score(reference: dict[str, Any], category: str) -> int:
    url = str(reference.get("url") or "").lower()
    tags = {str(tag).strip().lower() for tag in reference.get("tags") or ()}
    score = 0

    if category == "itw" and _looks_like_itw_reference(url):
        score += 60
    if category == "poc" and ("exploit" in tags or _looks_like_poc_reference(url)):
        score += 50
    if category == "vendor":
        if "vendor-advisory" in tags:
            score += 60
        if "patch" in tags:
            score += 30
        if "release-notes" in tags:
            score += 20
    if category == "research" and tags:
        score += 20

    if not _looks_like_low_signal_code_reference(url):
        score += 10
    if reference.get("name"):
        score += 5
    return score


def _looks_like_itw_reference(url: str) -> bool:
    return any(
        marker in url
        for marker in (
            "known-exploited",
            "known_exploited",
            "vulncheck-kev",
            "/kev",
            "catalog.cisa.gov/known-exploited",
        )
    )


def _looks_like_poc_reference(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    return any(
        marker in host or marker in path
        for marker in (
            "exploit-db.com",
            "packetstormsecurity.com",
            "/exploit",
            "/poc",
            "proof-of-concept",
        )
    ) or ("github.com" in host and any(marker in path for marker in ("/blob/", "/raw/", "/tree/", "exploit", "poc")))


def _looks_like_low_signal_code_reference(url: str) -> bool:
    lowered = url.lower()
    return any(
        marker in lowered
        for marker in (
            "/blob/",
            "/browser/",
            "#l",
            "#file",
            "/commit/",
            "/compare/",
        )
    )


def _get_publication_event_by_idempotency(session: Session, idempotency_key: str) -> PublicationEvent | None:
    return session.scalar(
        select(PublicationEvent)
        .where(PublicationEvent.idempotency_key == idempotency_key)
        .order_by(PublicationEvent.created_at.desc(), PublicationEvent.id.desc())
        .limit(1)
    )


def _get_successful_publication_event(
    session: Session,
    *,
    cve_id: UUID,
    event_type: PublicationEventType,
    target_name: str,
    content_hash: str,
) -> PublicationEvent | None:
    return session.scalar(
        select(PublicationEvent)
        .where(
            PublicationEvent.cve_id == cve_id,
            PublicationEvent.event_type == event_type,
            PublicationEvent.destination == target_name,
            PublicationEvent.content_hash == content_hash,
            PublicationEvent.status == PublicationEventStatus.PUBLISHED,
        )
        .order_by(PublicationEvent.published_at.desc(), PublicationEvent.id.desc())
        .limit(1)
    )


def _resolve_lineage_root_publication_event(
    session: Session,
    publication_event: PublicationEvent,
) -> PublicationEvent | None:
    current = publication_event
    seen_ids: set[UUID] = {publication_event.id}
    while current.baseline_publication_event_id is not None:
        next_event = _get_publication_event_by_id(session, current.baseline_publication_event_id)
        if next_event is None or next_event.id in seen_ids:
            break
        seen_ids.add(next_event.id)
        current = next_event
    return current


def _resolve_state(current_state: CveState, desired_state: CveState) -> CveState:
    if current_state == desired_state:
        return current_state
    try:
        return guard_transition(current_state, desired_state)
    except InvalidStateTransition:
        return current_state


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _serialize_classification(classification: Classification | None) -> dict[str, Any] | None:
    if classification is None:
        return None
    return {
        "id": str(classification.id),
        "classifier_version": classification.classifier_version,
        "outcome": classification.outcome.value,
        "reason_codes": list(classification.reason_codes),
        "details": classification.details,
        "canonical_name": classification.details.get("canonical_name"),
        "product_scope": classification.details.get("product_scope"),
    }


def _serialize_policy_decision(decision: PolicyDecision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "id": str(decision.id),
        "policy_snapshot_id": str(decision.policy_snapshot_id) if decision.policy_snapshot_id is not None else None,
        "policy_version": decision.policy_version,
        "decision": decision.decision.value,
        "deterministic_outcome": decision.deterministic_outcome.value
        if decision.deterministic_outcome is not None
        else None,
        "reason_codes": list(decision.reason_codes),
        "input_fingerprint": decision.input_fingerprint,
        "inputs_snapshot": decision.inputs_snapshot,
        "rationale": decision.rationale,
        "conflict_resolution": decision.conflict_resolution,
    }


def _serialize_policy_configuration(
    policy_snapshot: PolicyConfigurationSnapshot | None,
    decision: PolicyDecision | None,
) -> dict[str, Any] | None:
    if policy_snapshot is None and decision is None:
        return None
    return {
        "id": str(policy_snapshot.id) if policy_snapshot is not None else None,
        "policy_version": policy_snapshot.policy_version if policy_snapshot is not None else decision.policy_version,
        "config_fingerprint": policy_snapshot.config_fingerprint if policy_snapshot is not None else None,
        "snapshot": policy_snapshot.config_snapshot if policy_snapshot is not None else None,
    }


def _serialize_ai_review(ai_review: AIReview | None) -> dict[str, Any] | None:
    if ai_review is None:
        return None
    return {
        "id": str(ai_review.id),
        "model_name": ai_review.model_name,
        "prompt_version": ai_review.prompt_version,
        "outcome": ai_review.outcome.value,
        "schema_valid": ai_review.schema_valid,
        "advisory_payload": ai_review.advisory_payload,
    }


def _write_audit_event(
    session: Session,
    *,
    cve: CVE,
    entity_id: UUID,
    actor_type: AuditActorType,
    event_type: str,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="publication_event",
            entity_id=entity_id,
            actor_type=actor_type,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )


def _record_update_publication_metric(
    session: Session,
    *,
    prepared: PreparedPublication,
    result: str,
    observed_at: datetime | None,
    details: dict[str, Any],
) -> None:
    if prepared.event_type is not PublicationEventType.UPDATE:
        return
    increment_operational_metric(
        session,
        UPDATE_PUBLICATION_METRIC_KEY,
        dimensions={
            "event_type": prepared.event_type.value,
            "result": result,
            "target_name": prepared.target_name,
        },
        observed_at=observed_at,
        details={
            "idempotency_key": prepared.idempotency_key,
            "triggering_update_candidate_id": prepared.update_candidate.id if prepared.update_candidate is not None else None,
            "baseline_publication_event_id": (
                prepared.baseline_publication_event.id if prepared.baseline_publication_event is not None else None
            ),
            **details,
        },
    )


def _record_target_publication_metric(
    session: Session,
    *,
    prepared: PreparedPublication,
    result: str,
    observed_at: datetime | None,
    event: PublicationEvent,
    details: dict[str, Any],
) -> None:
    if prepared.target_name != "x":
        return
    increment_operational_metric(
        session,
        X_PUBLICATION_METRIC_KEY,
        dimensions={
            "event_type": prepared.event_type.value,
            "result": result,
            "target_name": prepared.target_name,
        },
        observed_at=observed_at,
        details={
            "idempotency_key": prepared.idempotency_key,
            "content_hash": prepared.content_hash,
            "event_status": event.status.value,
            "failure_category": (event.target_response or {}).get("failure_category"),
            "retryable": bool((event.target_response or {}).get("retryable")),
            "requires_reconciliation": bool((event.target_response or {}).get("requires_reconciliation")),
            "rate_limited": bool((event.target_response or {}).get("rate_limited")),
            "triggering_update_candidate_id": prepared.update_candidate.id if prepared.update_candidate is not None else None,
            "baseline_publication_event_id": (
                prepared.baseline_publication_event.id if prepared.baseline_publication_event is not None else None
            ),
            **details,
        },
    )
