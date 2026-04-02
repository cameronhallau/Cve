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
        summary="The product scope is ambiguous and would require a later AI review phase.",
    ),
    "classifier.fail_closed.ai_out_of_scope": ReasonCodeDefinition(
        code="classifier.fail_closed.ai_out_of_scope",
        title="AI Out Of Scope",
        summary="The current phase blocks AI routing, so ambiguous records stay fail-closed.",
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
