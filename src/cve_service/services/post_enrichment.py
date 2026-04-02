from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AuditEvent, CVE
from cve_service.models.enums import AuditActorType, CveState, PolicyDecisionOutcome
from cve_service.services.ai_review import AIReviewExecutionResult, AIReviewProvider, execute_ai_review
from cve_service.services.policy import PolicyGateResult, apply_policy_gate
from cve_service.services.state_machine import InvalidStateTransition, guard_transition


@dataclass(frozen=True, slots=True)
class PostEnrichmentWorkflowResult:
    cve_id: str
    state: CveState
    ai_review_id: UUID | None
    policy_decision_id: UUID | None
    ai_review_attempted: bool
    ai_review_skipped: bool
    ai_review_reused: bool
    ai_retry_override_applied: bool
    policy_reused: bool
    deferred: bool
    deferred_reason_codes: tuple[str, ...]


def process_post_enrichment_workflow(
    session: Session,
    cve_id: str,
    provider: AIReviewProvider,
    *,
    requested_at: datetime | None = None,
    evaluated_at: datetime | None = None,
    retry_ai_review: bool = False,
    actor_type: AuditActorType = AuditActorType.WORKER,
) -> PostEnrichmentWorkflowResult:
    cve = _get_cve_by_public_id(session, cve_id)
    state_before = cve.state
    state_after_start = _start_post_enrichment_state(cve.state)
    if state_after_start != cve.state:
        cve.state = state_after_start
        session.flush()

    _write_audit_event(
        session,
        cve=cve,
        actor_type=actor_type,
        event_type="workflow.post_enrichment_started",
        state_before=state_before,
        state_after=cve.state,
        details={
            "requested_at": _serialize_datetime(_normalize_datetime(requested_at)),
            "evaluated_at": _serialize_datetime(_normalize_datetime(evaluated_at)),
        },
    )

    ai_result = execute_ai_review(
        session,
        cve_id,
        provider,
        requested_at=requested_at,
        retry_override=retry_ai_review,
    )
    policy_result: PolicyGateResult | None = None

    if ai_result.review_id is not None and ai_result.schema_valid is False:
        deferred_reason_codes = ("policy.defer.ai_invalid_review",)
        _write_deferred_event(
            session,
            cve=cve,
            actor_type=actor_type,
            source="ai_review",
            reason_codes=deferred_reason_codes,
            details={
                "review_id": str(ai_result.review_id) if ai_result.review_id is not None else None,
                "validation_errors": list(ai_result.validation_errors),
                "retryable": True,
            },
        )
        session.flush()
        return _finalize_result(
            session,
            cve=cve,
            actor_type=actor_type,
            ai_result=ai_result,
            policy_result=None,
            deferred_reason_codes=deferred_reason_codes,
        )

    if cve.state in {CveState.POLICY_PENDING, CveState.PUBLISH_PENDING, CveState.DEFERRED}:
        policy_result = apply_policy_gate(session, cve_id, evaluated_at=evaluated_at)
        if policy_result.decision is PolicyDecisionOutcome.DEFER:
            _write_deferred_event(
                session,
                cve=cve,
                actor_type=actor_type,
                source="policy_gate",
                reason_codes=policy_result.reason_codes,
                details={
                    "decision_id": str(policy_result.decision_id),
                    "retryable": True,
                    "reused": policy_result.reused,
                },
            )

    session.flush()
    return _finalize_result(
        session,
        cve=cve,
        actor_type=actor_type,
        ai_result=ai_result,
        policy_result=policy_result,
        deferred_reason_codes=policy_result.reason_codes if policy_result is not None and policy_result.decision is PolicyDecisionOutcome.DEFER else (),
    )


def _finalize_result(
    session: Session,
    *,
    cve: CVE,
    actor_type: AuditActorType,
    ai_result: AIReviewExecutionResult,
    policy_result: PolicyGateResult | None,
    deferred_reason_codes: tuple[str, ...],
) -> PostEnrichmentWorkflowResult:
    _write_audit_event(
        session,
        cve=cve,
        actor_type=actor_type,
        event_type="workflow.post_enrichment_completed",
        state_before=None,
        state_after=cve.state,
        details={
            "ai_review_id": str(ai_result.review_id) if ai_result.review_id is not None else None,
            "policy_decision_id": str(policy_result.decision_id) if policy_result is not None else None,
            "ai_review_attempted": ai_result.review_attempted,
            "ai_review_skipped": ai_result.skipped,
            "ai_review_reused": ai_result.reused,
            "ai_retry_override_applied": ai_result.retry_override_applied,
            "policy_reused": policy_result.reused if policy_result is not None else False,
            "deferred": cve.state is CveState.DEFERRED,
            "deferred_reason_codes": list(deferred_reason_codes),
        },
    )
    session.flush()
    return PostEnrichmentWorkflowResult(
        cve_id=cve.cve_id,
        state=cve.state,
        ai_review_id=ai_result.review_id,
        policy_decision_id=policy_result.decision_id if policy_result is not None else None,
        ai_review_attempted=ai_result.review_attempted,
        ai_review_skipped=ai_result.skipped,
        ai_review_reused=ai_result.reused,
        ai_retry_override_applied=ai_result.retry_override_applied,
        policy_reused=policy_result.reused if policy_result is not None else False,
        deferred=cve.state is CveState.DEFERRED,
        deferred_reason_codes=deferred_reason_codes,
    )


def _start_post_enrichment_state(current_state: CveState) -> CveState:
    if current_state in {CveState.CLASSIFIED, CveState.DEFERRED}:
        return _resolve_state(current_state, CveState.ENRICHMENT_PENDING)
    return current_state


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown cve_id: {cve_id}")
    return cve


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _resolve_state(current_state: CveState, desired_state: CveState) -> CveState:
    if current_state == desired_state:
        return current_state

    try:
        return guard_transition(current_state, desired_state)
    except InvalidStateTransition:
        return current_state


def _write_audit_event(
    session: Session,
    *,
    cve: CVE,
    actor_type: AuditActorType,
    event_type: str,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="workflow",
            entity_id=None,
            actor_type=actor_type,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )


def _write_deferred_event(
    session: Session,
    *,
    cve: CVE,
    actor_type: AuditActorType,
    source: str,
    reason_codes: tuple[str, ...],
    details: dict[str, Any],
) -> None:
    _write_audit_event(
        session,
        cve=cve,
        actor_type=actor_type,
        event_type="workflow.deferred_recorded",
        state_before=cve.state,
        state_after=cve.state,
        details={
            "source": source,
            "reason_codes": list(reason_codes),
            **details,
        },
    )
