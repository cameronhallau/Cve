from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

REASON_CODE_REGISTRY_VERSION = "reason-codes.v1"


@dataclass(frozen=True, slots=True)
class ReasonCodeDefinition:
    code: str
    title: str
    summary: str


class UnknownReasonCodeError(ValueError):
    """Raised when a reason code is missing from the registry."""


_REGISTRY: dict[str, ReasonCodeDefinition] = {
    "classifier.candidate.enterprise_high_or_critical": ReasonCodeDefinition(
        code="classifier.candidate.enterprise_high_or_critical",
        title="Enterprise High Or Critical",
        summary="The product is recognized as enterprise-relevant and the severity is High or Critical.",
    ),
    "classifier.deny.consumer_only_product": ReasonCodeDefinition(
        code="classifier.deny.consumer_only_product",
        title="Consumer Only Product",
        summary="The product matches a consumer-only catalog entry and is denied by deterministic policy.",
    ),
    "classifier.defer.unsupported_severity": ReasonCodeDefinition(
        code="classifier.defer.unsupported_severity",
        title="Unsupported Severity",
        summary="The record severity is outside the High or Critical publishable range.",
    ),
    "classifier.needs_ai.unknown_product_scope": ReasonCodeDefinition(
        code="classifier.needs_ai.unknown_product_scope",
        title="Unknown Product Scope",
        summary="The product scope is ambiguous and must be routed to AI review before policy.",
    ),
    "classifier.fail_closed.ai_out_of_scope": ReasonCodeDefinition(
        code="classifier.fail_closed.ai_out_of_scope",
        title="AI Out Of Scope",
        summary="The current phase blocks AI routing, so ambiguous records stay fail-closed.",
    ),
    "policy.defer.ai_invalid_review": ReasonCodeDefinition(
        code="policy.defer.ai_invalid_review",
        title="Invalid AI Review",
        summary="The latest AI review response was invalid, so policy fails closed and defers publication.",
    ),
    "policy.defer.ai_low_confidence": ReasonCodeDefinition(
        code="policy.defer.ai_low_confidence",
        title="Low AI Confidence",
        summary="The AI advisory confidence is too low to influence policy.",
    ),
    "policy.defer.ai_review_required": ReasonCodeDefinition(
        code="policy.defer.ai_review_required",
        title="AI Review Required",
        summary="The deterministic outcome is ambiguous and a valid AI review is required before policy can publish.",
    ),
    "policy.defer.ai_uncertain_enterprise_relevance": ReasonCodeDefinition(
        code="policy.defer.ai_uncertain_enterprise_relevance",
        title="AI Uncertain Enterprise Relevance",
        summary="The AI advisory did not clearly confirm enterprise relevance, so policy fails closed.",
    ),
    "policy.defer.ai_uncertain_exploit_path": ReasonCodeDefinition(
        code="policy.defer.ai_uncertain_exploit_path",
        title="AI Uncertain Exploit Path",
        summary="The AI advisory did not clearly confirm an internet-exploitable path, so policy fails closed.",
    ),
    "policy.defer.ai_evidence_conflict": ReasonCodeDefinition(
        code="policy.defer.ai_evidence_conflict",
        title="AI Evidence Conflict",
        summary="The AI advisory conflicts with deterministic exploit evidence signals, so policy fails closed.",
    ),
    "policy.defer.awaiting_exploit_evidence": ReasonCodeDefinition(
        code="policy.defer.awaiting_exploit_evidence",
        title="Awaiting Exploit Evidence",
        summary="The candidate is enterprise-relevant, but current PoC and ITW evidence is insufficient to publish.",
    ),
    "policy.defer.deterministic_defer": ReasonCodeDefinition(
        code="policy.defer.deterministic_defer",
        title="Deterministic Defer",
        summary="The deterministic classifier deferred the record, so policy keeps it closed.",
    ),
    "policy.publish.ai_confirmed_with_itw": ReasonCodeDefinition(
        code="policy.publish.ai_confirmed_with_itw",
        title="AI Confirmed With ITW",
        summary="AI confirmed enterprise relevance and exploitability, and in-the-wild evidence is present.",
    ),
    "policy.publish.ai_confirmed_with_poc": ReasonCodeDefinition(
        code="policy.publish.ai_confirmed_with_poc",
        title="AI Confirmed With PoC",
        summary="AI confirmed enterprise relevance and exploitability, and trusted PoC evidence is present.",
    ),
    "policy.publish.enterprise_candidate_with_itw": ReasonCodeDefinition(
        code="policy.publish.enterprise_candidate_with_itw",
        title="Enterprise Candidate With ITW",
        summary="The deterministic enterprise candidate has in-the-wild evidence and is publishable.",
    ),
    "policy.publish.enterprise_candidate_with_poc": ReasonCodeDefinition(
        code="policy.publish.enterprise_candidate_with_poc",
        title="Enterprise Candidate With PoC",
        summary="The deterministic enterprise candidate has trusted PoC evidence and is publishable.",
    ),
    "policy.suppress.ai_enterprise_unlikely": ReasonCodeDefinition(
        code="policy.suppress.ai_enterprise_unlikely",
        title="AI Enterprise Unlikely",
        summary="The AI advisory assessed the record as unlikely to be enterprise-relevant.",
    ),
    "policy.suppress.hard_deterministic_deny": ReasonCodeDefinition(
        code="policy.suppress.hard_deterministic_deny",
        title="Hard Deterministic Deny",
        summary="A deterministic hard deny remains absolute and suppresses the record.",
    ),
    "update.material.evidence_itw_status_changed": ReasonCodeDefinition(
        code="update.material.evidence_itw_status_changed",
        title="ITW Status Changed",
        summary="The in-the-wild evidence posture changed since the last published state and requires an update candidate.",
    ),
    "update.material.evidence_poc_status_changed": ReasonCodeDefinition(
        code="update.material.evidence_poc_status_changed",
        title="PoC Status Changed",
        summary="The proof-of-concept evidence posture changed since the last published state and requires an update candidate.",
    ),
}


def get_reason_code_definition(code: str) -> ReasonCodeDefinition:
    try:
        return _REGISTRY[code]
    except KeyError as exc:
        raise UnknownReasonCodeError(f"unknown reason code: {code}") from exc


def validate_reason_codes(codes: Iterable[str]) -> list[str]:
    resolved = [get_reason_code_definition(code).code for code in codes]
    return resolved


def reason_code_registry_snapshot(codes: Iterable[str]) -> list[dict[str, str]]:
    return [
        {
            **asdict(get_reason_code_definition(code)),
            "registry_version": REASON_CODE_REGISTRY_VERSION,
        }
        for code in codes
    ]
