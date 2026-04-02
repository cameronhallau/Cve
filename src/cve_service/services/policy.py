from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AIReview, AuditEvent, CVE, Classification, PolicyDecision
from cve_service.models.enums import (
    AIReviewOutcome,
    AuditActorType,
    ClassificationOutcome,
    CveState,
    EvidenceStatus,
    PolicyDecisionOutcome,
)
from cve_service.services.ai_review import fingerprint_payload
from cve_service.services.reason_codes import REASON_CODE_REGISTRY_VERSION, reason_code_registry_snapshot, validate_reason_codes
from cve_service.services.state_machine import InvalidStateTransition, guard_transition

POLICY_VERSION = "phase3-policy.v1"
AI_CONFIDENCE_THRESHOLD = 0.75


@dataclass(frozen=True, slots=True)
class PolicyEvaluationInput:
    cve_id: str
    severity: str | None
    deterministic_outcome: ClassificationOutcome
    deterministic_reason_codes: tuple[str, ...]
    poc_status: EvidenceStatus
    poc_confidence: float | None
    itw_status: EvidenceStatus
    itw_confidence: float | None
    ai_review_outcome: AIReviewOutcome | None
    ai_schema_valid: bool
    ai_advisory: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class PolicyEvaluationResult:
    decision: PolicyDecisionOutcome
    reason_codes: tuple[str, ...]
    ai_fields_considered: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicyGateResult:
    cve_id: str
    decision_id: UUID
    decision: PolicyDecisionOutcome
    state: CveState
    reason_codes: tuple[str, ...]
    ai_review_id: UUID | None
    reused: bool


def evaluate_policy_inputs(inputs: PolicyEvaluationInput) -> PolicyEvaluationResult:
    if inputs.deterministic_outcome is ClassificationOutcome.DENY:
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.SUPPRESS,
            reason_codes=tuple(validate_reason_codes(["policy.suppress.hard_deterministic_deny"])),
            ai_fields_considered=(),
        )

    if inputs.deterministic_outcome is ClassificationOutcome.DEFER:
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes(["policy.defer.deterministic_defer"])),
            ai_fields_considered=(),
        )

    if inputs.deterministic_outcome is ClassificationOutcome.CANDIDATE:
        if inputs.itw_status is EvidenceStatus.PRESENT:
            return PolicyEvaluationResult(
                decision=PolicyDecisionOutcome.PUBLISH,
                reason_codes=tuple(validate_reason_codes(["policy.publish.enterprise_candidate_with_itw"])),
                ai_fields_considered=(),
            )
        if inputs.poc_status is EvidenceStatus.PRESENT:
            return PolicyEvaluationResult(
                decision=PolicyDecisionOutcome.PUBLISH,
                reason_codes=tuple(validate_reason_codes(["policy.publish.enterprise_candidate_with_poc"])),
                ai_fields_considered=(),
            )
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes(["policy.defer.awaiting_exploit_evidence"])),
            ai_fields_considered=(),
        )

    if not inputs.ai_schema_valid:
        reason = "policy.defer.ai_invalid_review" if inputs.ai_review_outcome is AIReviewOutcome.INVALID else "policy.defer.ai_review_required"
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes([reason])),
            ai_fields_considered=(),
        )

    assert inputs.ai_advisory is not None
    ai_fields_considered = (
        "enterprise_relevance_assessment",
        "exploit_path_assessment",
        "confidence",
    )
    ai_confidence = float(inputs.ai_advisory["confidence"])
    enterprise_relevance = inputs.ai_advisory["enterprise_relevance_assessment"]
    exploit_path = inputs.ai_advisory["exploit_path_assessment"]

    if ai_confidence < AI_CONFIDENCE_THRESHOLD:
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes(["policy.defer.ai_low_confidence"])),
            ai_fields_considered=ai_fields_considered,
        )
    if enterprise_relevance == "enterprise_unlikely":
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.SUPPRESS,
            reason_codes=tuple(validate_reason_codes(["policy.suppress.ai_enterprise_unlikely"])),
            ai_fields_considered=ai_fields_considered,
        )
    if enterprise_relevance != "enterprise_relevant":
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes(["policy.defer.ai_uncertain_enterprise_relevance"])),
            ai_fields_considered=ai_fields_considered,
        )
    if exploit_path != "internet_exploitable":
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes(["policy.defer.ai_uncertain_exploit_path"])),
            ai_fields_considered=ai_fields_considered,
        )
    if inputs.poc_status is EvidenceStatus.ABSENT and inputs.itw_status is EvidenceStatus.ABSENT:
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=tuple(validate_reason_codes(["policy.defer.ai_evidence_conflict"])),
            ai_fields_considered=ai_fields_considered,
        )
    if inputs.itw_status is EvidenceStatus.PRESENT:
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.PUBLISH,
            reason_codes=tuple(validate_reason_codes(["policy.publish.ai_confirmed_with_itw"])),
            ai_fields_considered=ai_fields_considered,
        )
    if inputs.poc_status is EvidenceStatus.PRESENT:
        return PolicyEvaluationResult(
            decision=PolicyDecisionOutcome.PUBLISH,
            reason_codes=tuple(validate_reason_codes(["policy.publish.ai_confirmed_with_poc"])),
            ai_fields_considered=ai_fields_considered,
        )
    return PolicyEvaluationResult(
        decision=PolicyDecisionOutcome.DEFER,
        reason_codes=tuple(validate_reason_codes(["policy.defer.awaiting_exploit_evidence"])),
        ai_fields_considered=ai_fields_considered,
    )


def apply_policy_gate(
    session: Session,
    cve_id: str,
    *,
    evaluated_at: datetime | None = None,
    policy_version: str = POLICY_VERSION,
) -> PolicyGateResult:
    cve = _get_cve_by_public_id(session, cve_id)
    classification = _get_latest_classification(session, cve.id)
    if classification is None:
        raise ValueError(f"no classification found for {cve_id}")
    ai_review = _get_latest_ai_review(session, cve.id)
    effective_evaluated_at = _normalize_datetime(evaluated_at) or datetime.now(UTC)

    working_state = _prepare_policy_state(cve.state)
    if working_state != cve.state:
        cve.state = working_state
        session.flush()

    inputs = PolicyEvaluationInput(
        cve_id=cve.cve_id,
        severity=cve.severity,
        deterministic_outcome=classification.outcome,
        deterministic_reason_codes=tuple(classification.reason_codes),
        poc_status=cve.poc_status,
        poc_confidence=cve.poc_confidence,
        itw_status=cve.itw_status,
        itw_confidence=cve.itw_confidence,
        ai_review_outcome=ai_review.outcome if ai_review is not None else None,
        ai_schema_valid=bool(ai_review is not None and ai_review.schema_valid),
        ai_advisory=ai_review.advisory_payload if ai_review is not None and ai_review.schema_valid else None,
    )
    evaluation = evaluate_policy_inputs(inputs)

    inputs_snapshot = build_policy_inputs_snapshot(
        cve=cve,
        classification=classification,
        ai_review=ai_review,
        effective_evaluated_at=effective_evaluated_at,
        ai_fields_considered=evaluation.ai_fields_considered,
    )
    input_fingerprint = fingerprint_payload(inputs_snapshot)
    reusable_decision = _get_reusable_policy_decision(session, cve.id, input_fingerprint)
    if reusable_decision is not None:
        state_before = cve.state
        state_after = _policy_target_state(cve.state, reusable_decision.decision)
        cve.state = state_after
        cve.last_policy_outcome = reusable_decision.decision
        cve.last_decision_at = effective_evaluated_at
        session.flush()

        _write_audit_event(
            session,
            cve=cve,
            entity_id=reusable_decision.id,
            state_before=state_before,
            state_after=state_after,
            details={
                "policy_version": reusable_decision.policy_version,
                "decision": reusable_decision.decision.value,
                "reason_codes": list(reusable_decision.reason_codes),
                "ai_review_id": str(ai_review.id) if ai_review is not None else None,
                "ai_advisory_fields_considered": list(evaluation.ai_fields_considered),
                "input_fingerprint": input_fingerprint,
                "reused": True,
            },
            event_type="policy.decision_reused",
        )
        session.flush()

        return PolicyGateResult(
            cve_id=cve.cve_id,
            decision_id=reusable_decision.id,
            decision=reusable_decision.decision,
            state=cve.state,
            reason_codes=tuple(reusable_decision.reason_codes),
            ai_review_id=reusable_decision.ai_review_id,
            reused=True,
        )

    state_before = cve.state
    state_after = _policy_target_state(cve.state, evaluation.decision)
    cve.state = state_after
    cve.last_policy_outcome = evaluation.decision
    cve.last_decision_at = effective_evaluated_at

    decision = PolicyDecision(
        cve_id=cve.id,
        ai_review_id=ai_review.id if ai_review is not None else None,
        policy_version=policy_version,
        input_fingerprint=input_fingerprint,
        decision=evaluation.decision,
        deterministic_outcome=classification.outcome,
        reason_codes=list(evaluation.reason_codes),
        inputs_snapshot=inputs_snapshot,
    )
    session.add(decision)
    session.flush()

    _write_audit_event(
        session,
        cve=cve,
        entity_id=decision.id,
        state_before=state_before,
        state_after=state_after,
        details={
            "policy_version": policy_version,
            "decision": evaluation.decision.value,
            "reason_codes": list(evaluation.reason_codes),
            "ai_review_id": str(ai_review.id) if ai_review is not None else None,
            "ai_advisory_fields_considered": list(evaluation.ai_fields_considered),
            "input_fingerprint": input_fingerprint,
            "reused": False,
        },
    )
    session.flush()

    return PolicyGateResult(
        cve_id=cve.cve_id,
        decision_id=decision.id,
        decision=evaluation.decision,
        state=cve.state,
        reason_codes=evaluation.reason_codes,
        ai_review_id=ai_review.id if ai_review is not None else None,
        reused=False,
    )


def _prepare_policy_state(current_state: CveState) -> CveState:
    if current_state in {CveState.CLASSIFIED, CveState.ENRICHMENT_PENDING, CveState.AI_REVIEW_PENDING, CveState.DEFERRED}:
        return _resolve_state(current_state, CveState.POLICY_PENDING)
    return current_state


def _policy_target_state(current_state: CveState, decision: PolicyDecisionOutcome) -> CveState:
    if decision is PolicyDecisionOutcome.PUBLISH:
        desired_state = CveState.PUBLISH_PENDING
    elif decision is PolicyDecisionOutcome.DEFER:
        desired_state = CveState.DEFERRED
    else:
        desired_state = CveState.SUPPRESSED
    return _resolve_state(current_state, desired_state)


def build_policy_inputs_snapshot(
    *,
    cve: CVE,
    classification: Classification,
    ai_review: AIReview | None,
    effective_evaluated_at: datetime,
    ai_fields_considered: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "evaluated_at": _serialize_datetime(effective_evaluated_at),
        "severity": cve.severity,
        "deterministic": {
            "outcome": classification.outcome.value,
            "reason_codes": list(classification.reason_codes),
            "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
            "reason_code_definitions": reason_code_registry_snapshot(classification.reason_codes),
            "classification_id": str(classification.id),
            "snapshot_id": str(classification.snapshot_id) if classification.snapshot_id is not None else None,
        },
        "evidence": {
            "poc_status": cve.poc_status.value,
            "poc_confidence": cve.poc_confidence,
            "itw_status": cve.itw_status.value,
            "itw_confidence": cve.itw_confidence,
        },
        "ai_review": _serialize_ai_review(ai_review),
        "ai_advisory_fields_considered": list(ai_fields_considered),
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
        "raw_response": ai_review.raw_response,
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


def _get_reusable_policy_decision(session: Session, cve_pk: UUID, input_fingerprint: str) -> PolicyDecision | None:
    return session.scalar(
        select(PolicyDecision)
        .where(
            PolicyDecision.cve_id == cve_pk,
            PolicyDecision.input_fingerprint == input_fingerprint,
        )
        .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
        .limit(1)
    )


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
        return CveState.SUPPRESSED


def _write_audit_event(
    session: Session,
    *,
    cve: CVE,
    entity_id: UUID,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
    event_type: str = "policy.decision_made",
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="policy_decision",
            entity_id=entity_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )
