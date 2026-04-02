from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AIReview, AuditEvent, CVE, Classification
from cve_service.models.enums import AIReviewOutcome, AuditActorType, ClassificationOutcome, CveState
from cve_service.services.state_machine import InvalidStateTransition, guard_transition

REQUEST_SCHEMA_VERSION = "phase3-ai-review-request.v1"
PROMPT_VERSION = "phase3-ai-review.v1"


class AIReviewProvider(Protocol):
    def review(self, request: "AIProviderRequest") -> "AIProviderResponse":
        """Return a raw JSON object or JSON string for the AI review response."""


@dataclass(frozen=True, slots=True)
class AIProviderRequest:
    request_payload: dict[str, Any]
    request_schema: dict[str, Any]
    response_schema: dict[str, Any]
    prompt_version: str


@dataclass(frozen=True, slots=True)
class AIProviderResponse:
    model_name: str
    payload: dict[str, Any] | str
    prompt_version: str | None = None


@dataclass(frozen=True, slots=True)
class AIRouteDecision:
    cve_id: str
    should_route: bool
    advance_to_policy: bool
    reason: str
    classification_outcome: ClassificationOutcome
    current_state: CveState


@dataclass(frozen=True, slots=True)
class AIResponseValidation:
    schema_valid: bool
    outcome: AIReviewOutcome
    advisory_payload: dict[str, Any]
    raw_response: dict[str, Any]
    validation_errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AIReviewExecutionResult:
    cve_id: str
    review_attempted: bool
    skipped: bool
    route_reason: str
    state: CveState
    review_id: UUID | None
    schema_valid: bool | None
    outcome: AIReviewOutcome | None
    validation_errors: tuple[str, ...]


def build_ai_review_input_pack(
    session: Session,
    cve_id: str,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    cve = _get_cve_by_public_id(session, cve_id)
    classification = _get_latest_classification(session, cve.id)
    if classification is None:
        raise ValueError(f"no classification found for {cve_id}")

    request_pack = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "prompt_version": PROMPT_VERSION,
        "generated_at": _serialize_datetime(_normalize_datetime(generated_at) or datetime.now(UTC)),
        "cve_id": cve.cve_id,
        "title": cve.title,
        "description": cve.description,
        "severity": cve.severity,
        "source_modified_at": _serialize_datetime(cve.source_modified_at),
        "deterministic": {
            "outcome": classification.outcome.value,
            "confidence": classification.confidence,
            "reason_codes": list(classification.reason_codes),
            "product_scope": classification.details.get("product_scope"),
            "canonical_name": classification.details.get("canonical_name"),
            "ai_route": {
                "eligible": bool(classification.details.get("ai_route", {}).get("eligible", False)),
                "allowed": bool(classification.details.get("ai_route", {}).get("allowed", False)),
                "blocked_reason": classification.details.get("ai_route", {}).get("blocked_reason"),
            },
        },
        "evidence": {
            "poc_status": cve.poc_status.value,
            "poc_confidence": cve.poc_confidence,
            "itw_status": cve.itw_status.value,
            "itw_confidence": cve.itw_confidence,
        },
        "task": {
            "review_focus": (
                "Assess enterprise relevance and likely exploit path for this ambiguous High/Critical CVE. "
                "AI is advisory only and must not invent deterministic decisions."
            ),
            "allowed_output_fields": [
                "cve_id",
                "enterprise_relevance_assessment",
                "exploit_path_assessment",
                "confidence",
                "reasoning_summary",
            ],
            "constraints": [
                "Return JSON only and match the response schema exactly.",
                "Do not override deterministic hard denies.",
                "Treat PoC and ITW as separate signals.",
                "Prefer unknown when evidence is insufficient.",
            ],
        },
    }
    validation_errors = validate_json_schema("ai-review-request.schema.json", request_pack)
    if validation_errors:
        raise ValueError(f"invalid AI request pack for {cve_id}: {validation_errors}")
    return request_pack


def determine_ai_review_route(session: Session, cve_id: str) -> AIRouteDecision:
    cve = _get_cve_by_public_id(session, cve_id)
    classification = _get_latest_classification(session, cve.id)
    if classification is None:
        raise ValueError(f"no classification found for {cve_id}")

    if classification.outcome is ClassificationOutcome.DENY:
        return AIRouteDecision(
            cve_id=cve.cve_id,
            should_route=False,
            advance_to_policy=False,
            reason="hard_deterministic_deny",
            classification_outcome=classification.outcome,
            current_state=cve.state,
        )
    if classification.outcome is ClassificationOutcome.DEFER:
        return AIRouteDecision(
            cve_id=cve.cve_id,
            should_route=False,
            advance_to_policy=False,
            reason="deterministic_defer",
            classification_outcome=classification.outcome,
            current_state=cve.state,
        )
    if classification.outcome is ClassificationOutcome.CANDIDATE:
        return AIRouteDecision(
            cve_id=cve.cve_id,
            should_route=False,
            advance_to_policy=True,
            reason="deterministic_non_ambiguous",
            classification_outcome=classification.outcome,
            current_state=cve.state,
        )

    ai_route = classification.details.get("ai_route", {})
    if bool(ai_route.get("eligible", False)) and bool(ai_route.get("allowed", False)):
        return AIRouteDecision(
            cve_id=cve.cve_id,
            should_route=True,
            advance_to_policy=False,
            reason="ambiguous_product_scope",
            classification_outcome=classification.outcome,
            current_state=cve.state,
        )

    blocked_reason = ai_route.get("blocked_reason") or "deterministic_ai_route_blocked"
    return AIRouteDecision(
        cve_id=cve.cve_id,
        should_route=False,
        advance_to_policy=False,
        reason=str(blocked_reason),
        classification_outcome=classification.outcome,
        current_state=cve.state,
    )


def execute_ai_review(
    session: Session,
    cve_id: str,
    provider: AIReviewProvider,
    *,
    requested_at: datetime | None = None,
) -> AIReviewExecutionResult:
    cve = _get_cve_by_public_id(session, cve_id)
    classification = _get_latest_classification(session, cve.id)
    if classification is None:
        raise ValueError(f"no classification found for {cve_id}")

    route = determine_ai_review_route(session, cve_id)
    state_before = cve.state

    if not route.should_route:
        state_after = cve.state
        if route.advance_to_policy:
            state_after = _resolve_state(cve.state, CveState.POLICY_PENDING)
            cve.state = state_after
            session.flush()
        _write_audit_event(
            session,
            cve=cve,
            entity_type="ai_review",
            entity_id=None,
            actor_type=AuditActorType.SYSTEM,
            event_type="ai_review.skipped",
            state_before=state_before,
            state_after=state_after,
            details={
                "classification_outcome": classification.outcome.value,
                "route_reason": route.reason,
                "advance_to_policy": route.advance_to_policy,
                "evidence": _serialize_evidence_snapshot(cve),
            },
        )
        return AIReviewExecutionResult(
            cve_id=cve.cve_id,
            review_attempted=False,
            skipped=True,
            route_reason=route.reason,
            state=state_after,
            review_id=None,
            schema_valid=None,
            outcome=None,
            validation_errors=(),
        )

    request_pack = build_ai_review_input_pack(session, cve_id, generated_at=requested_at)
    cve.state = _resolve_state(cve.state, CveState.AI_REVIEW_PENDING)
    session.flush()

    provider_response = provider.review(
        AIProviderRequest(
            request_payload=request_pack,
            request_schema=load_schema("ai-review-request.schema.json"),
            response_schema=load_schema("ai-review-response.schema.json"),
            prompt_version=PROMPT_VERSION,
        )
    )
    validation = validate_ai_response(cve_id, provider_response.payload)
    ai_review = AIReview(
        cve_id=cve.id,
        model_name=provider_response.model_name,
        prompt_version=provider_response.prompt_version or PROMPT_VERSION,
        outcome=validation.outcome,
        schema_valid=validation.schema_valid,
        advisory_payload=validation.advisory_payload,
        raw_response=validation.raw_response,
    )
    session.add(ai_review)
    session.flush()

    cve.state = _resolve_state(
        cve.state,
        CveState.POLICY_PENDING if validation.schema_valid else CveState.SUPPRESSED,
    )
    session.flush()

    _write_audit_event(
        session,
        cve=cve,
        entity_type="ai_review",
        entity_id=ai_review.id,
        actor_type=AuditActorType.AI,
        event_type="ai_review.persisted",
        state_before=state_before,
        state_after=cve.state,
        details={
            "route_reason": route.reason,
            "request_pack": request_pack,
            "model_name": ai_review.model_name,
            "prompt_version": ai_review.prompt_version,
            "schema_valid": ai_review.schema_valid,
            "outcome": ai_review.outcome.value,
            "validation_errors": list(validation.validation_errors),
            "advisory_payload": ai_review.advisory_payload,
        },
    )

    return AIReviewExecutionResult(
        cve_id=cve.cve_id,
        review_attempted=True,
        skipped=False,
        route_reason=route.reason,
        state=cve.state,
        review_id=ai_review.id,
        schema_valid=ai_review.schema_valid,
        outcome=ai_review.outcome,
        validation_errors=validation.validation_errors,
    )


def validate_ai_response(cve_id: str, payload: dict[str, Any] | str) -> AIResponseValidation:
    raw_response: dict[str, Any] = {}
    validation_errors: list[str] = []
    parsed_payload: Any

    if isinstance(payload, str):
        raw_response["raw_text"] = payload
        try:
            parsed_payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            validation_errors.append(f"invalid_json: {exc.msg} at line {exc.lineno} column {exc.colno}")
            raw_response["validation_errors"] = list(validation_errors)
            return AIResponseValidation(
                schema_valid=False,
                outcome=AIReviewOutcome.INVALID,
                advisory_payload={},
                raw_response=raw_response,
                validation_errors=tuple(validation_errors),
            )
    else:
        parsed_payload = payload

    raw_response["provider_payload"] = parsed_payload
    if not isinstance(parsed_payload, dict):
        validation_errors.append("invalid_json_type: top-level value must be an object")
    else:
        validation_errors.extend(validate_json_schema("ai-review-response.schema.json", parsed_payload))
        if parsed_payload.get("cve_id") != cve_id:
            validation_errors.append(f"cve_id_mismatch: expected {cve_id}")

    if validation_errors:
        raw_response["validation_errors"] = list(validation_errors)
        return AIResponseValidation(
            schema_valid=False,
            outcome=AIReviewOutcome.INVALID,
            advisory_payload={},
            raw_response=raw_response,
            validation_errors=tuple(validation_errors),
        )

    advisory_payload = dict(parsed_payload)
    raw_response["validation_errors"] = []
    return AIResponseValidation(
        schema_valid=True,
        outcome=_derive_ai_review_outcome(advisory_payload),
        advisory_payload=advisory_payload,
        raw_response=raw_response,
        validation_errors=(),
    )


def validate_json_schema(schema_name: str, payload: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(load_schema(schema_name), format_checker=FormatChecker())
    return sorted(_format_error(error) for error in validator.iter_errors(payload))


@lru_cache(maxsize=None)
def load_schema(schema_name: str) -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / schema_name
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _derive_ai_review_outcome(advisory_payload: dict[str, Any]) -> AIReviewOutcome:
    enterprise_relevance = advisory_payload["enterprise_relevance_assessment"]
    exploit_path = advisory_payload["exploit_path_assessment"]
    if enterprise_relevance == "enterprise_unlikely":
        return AIReviewOutcome.ADVISORY_SUPPRESS
    if enterprise_relevance == "enterprise_relevant" and exploit_path == "internet_exploitable":
        return AIReviewOutcome.ADVISORY_PUBLISH
    return AIReviewOutcome.ADVISORY_DEFER


def _format_error(error) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    if path:
        return f"{path}: {error.message}"
    return error.message


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _serialize_evidence_snapshot(cve: CVE) -> dict[str, Any]:
    return {
        "poc_status": cve.poc_status.value,
        "poc_confidence": cve.poc_confidence,
        "itw_status": cve.itw_status.value,
        "itw_confidence": cve.itw_confidence,
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
    entity_type: str,
    entity_id: UUID | None,
    actor_type: AuditActorType,
    event_type: str,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_type=actor_type,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )
