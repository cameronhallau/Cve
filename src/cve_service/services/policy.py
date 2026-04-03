from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AIReview, AuditEvent, CVE, Classification, PolicyConfigurationSnapshot, PolicyDecision
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

POLICY_VERSION = "phase4-policy.v1"
POLICY_CONFIG_SCHEMA_VERSION = "phase4-policy-config.v1"
POLICY_RATIONALE_SCHEMA_VERSION = "phase4-policy-rationale.v1"
POLICY_CONFLICT_SCHEMA_VERSION = "phase4-policy-conflict-resolution.v1"
DEFAULT_AI_FIELDS = (
    "enterprise_relevance_assessment",
    "exploit_path_assessment",
    "confidence",
)
PUBLISHABLE_EXPLOIT_PATHS = {"internet_exploitable", "phishing_initial_access"}


@dataclass(frozen=True, slots=True)
class PolicyRuntimeConfig:
    ai_confidence_threshold: float = 0.75
    hard_deterministic_deny_absolute: bool = True
    deterministic_candidate_publish_on_itw: bool = True
    deterministic_candidate_publish_on_poc: bool = True
    ai_requires_exploit_evidence: bool = False
    fail_closed_on_ai_conflict: bool = True
    allowed_ai_fields: tuple[str, ...] = DEFAULT_AI_FIELDS


DEFAULT_POLICY_CONFIG = PolicyRuntimeConfig()


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
    rationale: dict[str, Any]
    conflict_resolution: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PolicyGateResult:
    cve_id: str
    decision_id: UUID
    policy_snapshot_id: UUID | None
    decision: PolicyDecisionOutcome
    state: CveState
    reason_codes: tuple[str, ...]
    ai_review_id: UUID | None
    reused: bool


def evaluate_policy_inputs(
    inputs: PolicyEvaluationInput,
    *,
    policy_config: PolicyRuntimeConfig = DEFAULT_POLICY_CONFIG,
) -> PolicyEvaluationResult:
    if inputs.deterministic_outcome is ClassificationOutcome.DENY:
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.SUPPRESS,
            reason_codes=("policy.suppress.hard_deterministic_deny",),
            ai_fields_considered=(),
            resolution_basis="hard_deterministic_deny",
            rationale_summary="Deterministic deny remains absolute and suppresses the CVE regardless of advisory signals.",
        )

    if inputs.deterministic_outcome is ClassificationOutcome.DEFER:
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=("policy.defer.deterministic_defer",),
            ai_fields_considered=(),
            resolution_basis="deterministic_defer",
            rationale_summary="Deterministic classification deferred the CVE, so policy keeps it fail-closed.",
        )

    if not inputs.ai_schema_valid:
        reason = "policy.defer.ai_invalid_review" if inputs.ai_review_outcome is AIReviewOutcome.INVALID else "policy.defer.ai_review_required"
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=(reason,),
            ai_fields_considered=(),
            resolution_basis="ai_review_unavailable",
            rationale_summary="AI review is missing or invalid, so the ambiguous case remains deferred.",
        )

    assert inputs.ai_advisory is not None
    ai_fields_considered = policy_config.allowed_ai_fields
    ai_confidence = float(inputs.ai_advisory["confidence"])
    enterprise_relevance = inputs.ai_advisory["enterprise_relevance_assessment"]
    exploit_path = inputs.ai_advisory["exploit_path_assessment"]

    if ai_confidence < policy_config.ai_confidence_threshold:
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=("policy.defer.ai_low_confidence",),
            ai_fields_considered=ai_fields_considered,
            resolution_basis="ai_low_confidence",
            rationale_summary="AI advisory confidence is below the configured threshold, so policy fails closed.",
        )
    if inputs.deterministic_outcome is ClassificationOutcome.CANDIDATE:
        if _is_publishable_exploit_path(exploit_path):
            return _result(
                inputs,
                policy_config=policy_config,
                decision=PolicyDecisionOutcome.PUBLISH,
                reason_codes=("policy.publish.enterprise_candidate_with_initial_access_path",),
                ai_fields_considered=ai_fields_considered,
                resolution_basis="enterprise_candidate_with_initial_access_path",
                rationale_summary="Enterprise candidate published because AI confirmed a direct internet exploit path or phishing-delivered initial access path.",
            )
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=("policy.defer.ai_uncertain_exploit_path",),
            ai_fields_considered=ai_fields_considered,
            resolution_basis="ai_uncertain_exploit_path",
            rationale_summary="AI advisory did not confirm a direct internet exploit path or phishing-delivered initial access path, so policy defers.",
        )

    if enterprise_relevance == "enterprise_unlikely":
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.SUPPRESS,
            reason_codes=("policy.suppress.ai_enterprise_unlikely",),
            ai_fields_considered=ai_fields_considered,
            resolution_basis="ai_enterprise_unlikely",
            rationale_summary="AI advisory assessed the CVE as enterprise-unlikely, so policy suppresses it.",
        )
    if enterprise_relevance != "enterprise_relevant":
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=("policy.defer.ai_uncertain_enterprise_relevance",),
            ai_fields_considered=ai_fields_considered,
            resolution_basis="ai_uncertain_enterprise_relevance",
            rationale_summary="AI advisory did not clearly confirm enterprise relevance, so policy defers.",
        )
    if not _is_publishable_exploit_path(exploit_path):
        return _result(
            inputs,
            policy_config=policy_config,
            decision=PolicyDecisionOutcome.DEFER,
            reason_codes=("policy.defer.ai_uncertain_exploit_path",),
            ai_fields_considered=ai_fields_considered,
            resolution_basis="ai_uncertain_exploit_path",
            rationale_summary="AI advisory did not confirm a direct internet exploit path or phishing-delivered initial access path, so policy defers.",
        )
    return _result(
        inputs,
        policy_config=policy_config,
        decision=PolicyDecisionOutcome.PUBLISH,
        reason_codes=("policy.publish.ai_confirmed_initial_access_path",),
        ai_fields_considered=ai_fields_considered,
        resolution_basis="ai_publish_with_initial_access_path",
        rationale_summary="AI advisory confirmed enterprise relevance and a direct internet exploit path or phishing-delivered initial access path, so policy publishes without waiting for PoC or ITW evidence.",
    )


def apply_policy_gate(
    session: Session,
    cve_id: str,
    *,
    evaluated_at: datetime | None = None,
    policy_version: str = POLICY_VERSION,
    policy_config: PolicyRuntimeConfig = DEFAULT_POLICY_CONFIG,
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
    evaluation = evaluate_policy_inputs(inputs, policy_config=policy_config)
    policy_config_snapshot = build_policy_configuration_snapshot(
        policy_version=policy_version,
        policy_config=policy_config,
    )
    policy_config_fingerprint = fingerprint_payload(policy_config_snapshot)
    policy_snapshot = _get_or_create_policy_snapshot(
        session,
        policy_version=policy_version,
        config_fingerprint=policy_config_fingerprint,
        config_snapshot=policy_config_snapshot,
    )

    inputs_snapshot = build_policy_inputs_snapshot(
        cve=cve,
        classification=classification,
        ai_review=ai_review,
        effective_evaluated_at=effective_evaluated_at,
        ai_fields_considered=evaluation.ai_fields_considered,
        policy_version=policy_version,
        policy_snapshot=policy_snapshot,
        policy_config_fingerprint=policy_config_fingerprint,
        policy_config_snapshot=policy_config_snapshot,
    )
    input_fingerprint = fingerprint_payload(build_policy_fingerprint_payload(inputs_snapshot))
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
                "policy_snapshot_id": str(reusable_decision.policy_snapshot_id)
                if reusable_decision.policy_snapshot_id is not None
                else None,
                "decision": reusable_decision.decision.value,
                "reason_codes": list(reusable_decision.reason_codes),
                "ai_review_id": str(ai_review.id) if ai_review is not None else None,
                "ai_advisory_fields_considered": list(evaluation.ai_fields_considered),
                "input_fingerprint": input_fingerprint,
                "rationale": reusable_decision.rationale,
                "conflict_resolution": reusable_decision.conflict_resolution,
                "reused": True,
            },
            event_type="policy.decision_reused",
        )
        session.flush()

        return PolicyGateResult(
            cve_id=cve.cve_id,
            decision_id=reusable_decision.id,
            policy_snapshot_id=reusable_decision.policy_snapshot_id,
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
        policy_snapshot_id=policy_snapshot.id,
        policy_version=policy_version,
        input_fingerprint=input_fingerprint,
        decision=evaluation.decision,
        deterministic_outcome=classification.outcome,
        reason_codes=list(evaluation.reason_codes),
        inputs_snapshot=inputs_snapshot,
        rationale=evaluation.rationale,
        conflict_resolution=evaluation.conflict_resolution,
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
            "policy_snapshot_id": str(policy_snapshot.id),
            "decision": evaluation.decision.value,
            "reason_codes": list(evaluation.reason_codes),
            "ai_review_id": str(ai_review.id) if ai_review is not None else None,
            "ai_advisory_fields_considered": list(evaluation.ai_fields_considered),
            "input_fingerprint": input_fingerprint,
            "rationale": evaluation.rationale,
            "conflict_resolution": evaluation.conflict_resolution,
            "reused": False,
        },
    )
    session.flush()

    return PolicyGateResult(
        cve_id=cve.cve_id,
        decision_id=decision.id,
        policy_snapshot_id=policy_snapshot.id,
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
    policy_version: str,
    policy_snapshot: PolicyConfigurationSnapshot,
    policy_config_fingerprint: str,
    policy_config_snapshot: dict[str, Any],
) -> dict[str, Any]:
    return {
        "evaluated_at": _serialize_datetime(effective_evaluated_at),
        "severity": cve.severity,
        "policy_configuration": {
            "policy_version": policy_version,
            "snapshot_id": str(policy_snapshot.id),
            "config_fingerprint": policy_config_fingerprint,
            "snapshot": policy_config_snapshot,
        },
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


def build_policy_configuration_snapshot(
    *,
    policy_version: str,
    policy_config: PolicyRuntimeConfig,
) -> dict[str, Any]:
    config_payload = asdict(policy_config)
    config_payload["allowed_ai_fields"] = list(policy_config.allowed_ai_fields)
    return {
        "schema_version": POLICY_CONFIG_SCHEMA_VERSION,
        "policy_version": policy_version,
        "principles": {
            "rules_first": True,
            "ai_advisory_only": True,
            "hard_deterministic_denies_absolute": policy_config.hard_deterministic_deny_absolute,
        },
        "thresholds": {
            "ai_confidence_threshold": policy_config.ai_confidence_threshold,
        },
        "publish_gates": {
            "deterministic_candidate_publish_on_itw": policy_config.deterministic_candidate_publish_on_itw,
            "deterministic_candidate_publish_on_poc": policy_config.deterministic_candidate_publish_on_poc,
            "ai_requires_exploit_evidence": policy_config.ai_requires_exploit_evidence,
            "fail_closed_on_ai_conflict": policy_config.fail_closed_on_ai_conflict,
        },
        "ai": {
            "allowed_fields": config_payload["allowed_ai_fields"],
        },
    }


def build_policy_fingerprint_payload(inputs_snapshot: dict[str, Any]) -> dict[str, Any]:
    policy_configuration = dict(inputs_snapshot["policy_configuration"])
    policy_configuration.pop("snapshot_id", None)
    return {
        "severity": inputs_snapshot["severity"],
        "policy_configuration": policy_configuration,
        "deterministic": inputs_snapshot["deterministic"],
        "evidence": inputs_snapshot["evidence"],
        "ai_review": inputs_snapshot["ai_review"],
        "ai_advisory_fields_considered": inputs_snapshot["ai_advisory_fields_considered"],
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


def _get_or_create_policy_snapshot(
    session: Session,
    *,
    policy_version: str,
    config_fingerprint: str,
    config_snapshot: dict[str, Any],
) -> PolicyConfigurationSnapshot:
    snapshot = session.scalar(
        select(PolicyConfigurationSnapshot)
        .where(PolicyConfigurationSnapshot.config_fingerprint == config_fingerprint)
        .order_by(PolicyConfigurationSnapshot.created_at.desc(), PolicyConfigurationSnapshot.id.desc())
        .limit(1)
    )
    if snapshot is not None:
        return snapshot

    snapshot = PolicyConfigurationSnapshot(
        policy_version=policy_version,
        config_fingerprint=config_fingerprint,
        config_snapshot=config_snapshot,
    )
    session.add(snapshot)
    session.flush()
    return snapshot


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


def _result(
    inputs: PolicyEvaluationInput,
    *,
    policy_config: PolicyRuntimeConfig,
    decision: PolicyDecisionOutcome,
    reason_codes: tuple[str, ...],
    ai_fields_considered: tuple[str, ...],
    resolution_basis: str,
    rationale_summary: str,
) -> PolicyEvaluationResult:
    validated_reason_codes = tuple(validate_reason_codes(reason_codes))
    return PolicyEvaluationResult(
        decision=decision,
        reason_codes=validated_reason_codes,
        ai_fields_considered=ai_fields_considered,
        rationale=_build_policy_rationale(
            inputs,
            decision=decision,
            reason_codes=validated_reason_codes,
            ai_fields_considered=ai_fields_considered,
            resolution_basis=resolution_basis,
            rationale_summary=rationale_summary,
        ),
        conflict_resolution=_build_conflict_resolution(
            inputs,
            policy_config=policy_config,
            decision=decision,
            reason_codes=validated_reason_codes,
            resolution_basis=resolution_basis,
        ),
    )


def _build_policy_rationale(
    inputs: PolicyEvaluationInput,
    *,
    decision: PolicyDecisionOutcome,
    reason_codes: tuple[str, ...],
    ai_fields_considered: tuple[str, ...],
    resolution_basis: str,
    rationale_summary: str,
) -> dict[str, Any]:
    return {
        "schema_version": POLICY_RATIONALE_SCHEMA_VERSION,
        "outcome": decision.value,
        "summary": rationale_summary,
        "resolution_basis": resolution_basis,
        "reason_codes": list(reason_codes),
        "reason_code_definitions": reason_code_registry_snapshot(reason_codes),
        "deterministic": {
            "outcome": inputs.deterministic_outcome.value,
            "reason_codes": list(inputs.deterministic_reason_codes),
            "reason_code_definitions": reason_code_registry_snapshot(inputs.deterministic_reason_codes),
        },
        "evidence": {
            "poc_status": inputs.poc_status.value,
            "poc_confidence": inputs.poc_confidence,
            "itw_status": inputs.itw_status.value,
            "itw_confidence": inputs.itw_confidence,
        },
        "ai": {
            "review_outcome": inputs.ai_review_outcome.value if inputs.ai_review_outcome is not None else None,
            "schema_valid": inputs.ai_schema_valid,
            "fields_considered": list(ai_fields_considered),
            "advisory_payload": inputs.ai_advisory,
        },
    }


def _build_conflict_resolution(
    inputs: PolicyEvaluationInput,
    *,
    policy_config: PolicyRuntimeConfig,
    decision: PolicyDecisionOutcome,
    reason_codes: tuple[str, ...],
    resolution_basis: str,
) -> dict[str, Any]:
    ai_signal = _derive_ai_signal(inputs, policy_config)
    evidence_signal = _derive_evidence_signal(inputs)
    conflicts: list[dict[str, Any]] = []

    if inputs.deterministic_outcome is ClassificationOutcome.DENY:
        if evidence_signal["decision_tendency"] == PolicyDecisionOutcome.PUBLISH.value:
            conflicts.append(
                {
                    "type": "deterministic_vs_evidence",
                    "deterministic_outcome": inputs.deterministic_outcome.value,
                    "evidence_tendency": evidence_signal["decision_tendency"],
                    "resolved_by": resolution_basis,
                    "rationale": "Hard deterministic deny overrides publishable evidence signals.",
                }
            )
        if ai_signal["decision_tendency"] == PolicyDecisionOutcome.PUBLISH.value:
            conflicts.append(
                {
                    "type": "deterministic_vs_ai",
                    "deterministic_outcome": inputs.deterministic_outcome.value,
                    "ai_tendency": ai_signal["decision_tendency"],
                    "resolved_by": resolution_basis,
                    "rationale": "Hard deterministic deny overrides optimistic AI advisory output.",
                }
            )

    if ai_signal["decision_tendency"] is not None and ai_signal["decision_tendency"] != decision.value:
        conflicts.append(
            {
                "type": "ai_vs_policy_outcome",
                "ai_tendency": ai_signal["decision_tendency"],
                "selected_outcome": decision.value,
                "resolved_by": resolution_basis,
                "rationale": "Policy selected a different durable outcome than the advisory AI tendency.",
            }
        )
    if evidence_signal["decision_tendency"] != decision.value:
        conflicts.append(
            {
                "type": "evidence_vs_policy_outcome",
                "evidence_tendency": evidence_signal["decision_tendency"],
                "selected_outcome": decision.value,
                "resolved_by": resolution_basis,
                "rationale": "Policy selected a different outcome than the current exploit-evidence posture.",
            }
        )

    deduped_conflicts: list[dict[str, Any]] = []
    seen = set()
    for conflict in conflicts:
        key = (
            conflict["type"],
            conflict.get("deterministic_outcome"),
            conflict.get("ai_tendency"),
            conflict.get("evidence_tendency"),
            conflict.get("selected_outcome"),
        )
        if key in seen:
            continue
        deduped_conflicts.append(conflict)
        seen.add(key)

    return {
        "schema_version": POLICY_CONFLICT_SCHEMA_VERSION,
        "has_conflict": bool(deduped_conflicts),
        "selected_outcome": decision.value,
        "selected_reason_codes": list(reason_codes),
        "resolution_basis": resolution_basis,
        "deterministic_signal": {
            "outcome": inputs.deterministic_outcome.value,
            "reason_codes": list(inputs.deterministic_reason_codes),
        },
        "evidence_signal": evidence_signal,
        "ai_signal": ai_signal,
        "conflicts": deduped_conflicts,
    }


def _derive_ai_signal(inputs: PolicyEvaluationInput, policy_config: PolicyRuntimeConfig) -> dict[str, Any]:
    if not inputs.ai_schema_valid or inputs.ai_advisory is None:
        return {
            "available": False,
            "schema_valid": inputs.ai_schema_valid,
            "decision_tendency": None,
            "confidence": None,
            "enterprise_relevance_assessment": None,
            "exploit_path_assessment": None,
        }

    confidence = float(inputs.ai_advisory["confidence"])
    enterprise_relevance = inputs.ai_advisory["enterprise_relevance_assessment"]
    exploit_path = inputs.ai_advisory["exploit_path_assessment"]
    if enterprise_relevance == "enterprise_unlikely":
        tendency = PolicyDecisionOutcome.SUPPRESS.value
    elif confidence < policy_config.ai_confidence_threshold:
        tendency = PolicyDecisionOutcome.DEFER.value
    elif (
        inputs.deterministic_outcome is ClassificationOutcome.CANDIDATE
        and _is_publishable_exploit_path(exploit_path)
    ):
        tendency = PolicyDecisionOutcome.PUBLISH.value
    elif enterprise_relevance != "enterprise_relevant" or not _is_publishable_exploit_path(exploit_path):
        tendency = PolicyDecisionOutcome.DEFER.value
    else:
        tendency = PolicyDecisionOutcome.PUBLISH.value

    return {
        "available": True,
        "schema_valid": True,
        "decision_tendency": tendency,
        "confidence": confidence,
        "enterprise_relevance_assessment": enterprise_relevance,
        "exploit_path_assessment": exploit_path,
        "reasoning_summary": inputs.ai_advisory.get("reasoning_summary"),
    }


def _is_publishable_exploit_path(exploit_path: str | None) -> bool:
    return exploit_path in PUBLISHABLE_EXPLOIT_PATHS


def _derive_evidence_signal(inputs: PolicyEvaluationInput) -> dict[str, Any]:
    if inputs.itw_status is EvidenceStatus.PRESENT:
        tendency = PolicyDecisionOutcome.PUBLISH.value
        basis = "itw_present"
    elif inputs.poc_status is EvidenceStatus.PRESENT:
        tendency = PolicyDecisionOutcome.PUBLISH.value
        basis = "poc_present"
    else:
        tendency = PolicyDecisionOutcome.DEFER.value
        basis = "exploit_evidence_insufficient"
    return {
        "decision_tendency": tendency,
        "basis": basis,
        "poc_status": inputs.poc_status.value,
        "poc_confidence": inputs.poc_confidence,
        "itw_status": inputs.itw_status.value,
        "itw_confidence": inputs.itw_confidence,
    }
