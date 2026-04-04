from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import (
    AIReview,
    AuditEvent,
    CVE,
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
    )
    content_hash = fingerprint_payload(content.as_payload())
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
    content = build_update_publish_content(update_candidate=update_candidate)
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
    return dict(metadata) if isinstance(metadata, dict) else {}


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
