from __future__ import annotations

from dataclasses import dataclass
import re

from cve_service.models.enums import ClassificationOutcome, CveState
from cve_service.services.product_registry import (
    PRODUCT_REGISTRY_VERSION,
    CanonicalProduct,
    canonicalize_product,
)
from cve_service.services.reason_codes import REASON_CODE_REGISTRY_VERSION, validate_reason_codes

CLASSIFIER_VERSION = "deterministic-classifier.v1"


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    outcome: ClassificationOutcome
    confidence: float
    reason_codes: tuple[str, ...]
    next_state: CveState
    ai_route_eligible: bool
    details: dict[str, object]


def normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().upper()


def classify_record(
    severity: str | None,
    product: CanonicalProduct,
    *,
    title: str | None = None,
    description: str | None = None,
) -> ClassificationResult:
    normalized_severity = normalize_severity(severity)

    if product.scope == "consumer_only":
        reason_codes = validate_reason_codes(["classifier.deny.consumer_only_product"])
        return ClassificationResult(
            outcome=ClassificationOutcome.DENY,
            confidence=1.0,
            reason_codes=tuple(reason_codes),
            next_state=CveState.SUPPRESSED,
            ai_route_eligible=False,
            details={
                "classifier_version": CLASSIFIER_VERSION,
                "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
                "product_registry_version": PRODUCT_REGISTRY_VERSION,
                "product_scope": product.scope,
                "canonical_vendor_name": product.canonical_vendor_name,
                "canonical_product_name": product.canonical_product_name,
                "canonical_name": product.canonical_name,
                "matched_vendor_alias": product.matched_vendor_alias,
                "matched_product_alias": product.matched_product_alias,
                "severity": normalized_severity,
                "ai_route": {"eligible": False, "allowed": False, "blocked_reason": None},
            },
        )

    if _is_non_critical_denial_of_service(normalized_severity, title=title, description=description):
        reason_codes = validate_reason_codes(["classifier.deny.non_critical_denial_of_service"])
        return ClassificationResult(
            outcome=ClassificationOutcome.DENY,
            confidence=1.0,
            reason_codes=tuple(reason_codes),
            next_state=CveState.SUPPRESSED,
            ai_route_eligible=False,
            details={
                "classifier_version": CLASSIFIER_VERSION,
                "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
                "product_registry_version": PRODUCT_REGISTRY_VERSION,
                "product_scope": product.scope,
                "canonical_vendor_name": product.canonical_vendor_name,
                "canonical_product_name": product.canonical_product_name,
                "canonical_name": product.canonical_name,
                "matched_vendor_alias": product.matched_vendor_alias,
                "matched_product_alias": product.matched_product_alias,
                "severity": normalized_severity,
                "ai_route": {"eligible": False, "allowed": False, "blocked_reason": None},
            },
        )

    if normalized_severity not in {"HIGH", "CRITICAL"}:
        reason_codes = validate_reason_codes(["classifier.defer.unsupported_severity"])
        return ClassificationResult(
            outcome=ClassificationOutcome.DEFER,
            confidence=1.0,
            reason_codes=tuple(reason_codes),
            next_state=CveState.SUPPRESSED,
            ai_route_eligible=False,
            details={
                "classifier_version": CLASSIFIER_VERSION,
                "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
                "product_registry_version": PRODUCT_REGISTRY_VERSION,
                "product_scope": product.scope,
                "canonical_vendor_name": product.canonical_vendor_name,
                "canonical_product_name": product.canonical_product_name,
                "canonical_name": product.canonical_name,
                "matched_vendor_alias": product.matched_vendor_alias,
                "matched_product_alias": product.matched_product_alias,
                "severity": normalized_severity,
                "ai_route": {"eligible": False, "allowed": False, "blocked_reason": None},
            },
        )

    if product.scope == "unknown":
        reason_codes = validate_reason_codes(
            [
                "classifier.needs_ai.unknown_product_scope",
                "classifier.fail_closed.ai_out_of_scope",
            ]
        )
        return ClassificationResult(
            outcome=ClassificationOutcome.NEEDS_AI,
            confidence=0.35,
            reason_codes=("classifier.needs_ai.unknown_product_scope",),
            next_state=CveState.CLASSIFIED,
            ai_route_eligible=True,
            details={
                "classifier_version": CLASSIFIER_VERSION,
                "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
                "product_registry_version": PRODUCT_REGISTRY_VERSION,
                "product_scope": product.scope,
                "canonical_vendor_name": product.canonical_vendor_name,
                "canonical_product_name": product.canonical_product_name,
                "canonical_name": product.canonical_name,
                "matched_vendor_alias": product.matched_vendor_alias,
                "matched_product_alias": product.matched_product_alias,
                "severity": normalized_severity,
                "ai_route": {"eligible": True, "allowed": True, "blocked_reason": None},
            },
        )

    reason_codes = validate_reason_codes(["classifier.candidate.enterprise_high_or_critical"])
    return ClassificationResult(
        outcome=ClassificationOutcome.CANDIDATE,
        confidence=0.95,
        reason_codes=tuple(reason_codes),
        next_state=CveState.CLASSIFIED,
        ai_route_eligible=False,
        details={
            "classifier_version": CLASSIFIER_VERSION,
            "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
            "product_registry_version": PRODUCT_REGISTRY_VERSION,
            "product_scope": product.scope,
            "canonical_vendor_name": product.canonical_vendor_name,
            "canonical_product_name": product.canonical_product_name,
            "canonical_name": product.canonical_name,
            "matched_vendor_alias": product.matched_vendor_alias,
            "matched_product_alias": product.matched_product_alias,
            "severity": normalized_severity,
            "ai_route": {"eligible": False, "allowed": False, "blocked_reason": None},
        },
    )


def _is_non_critical_denial_of_service(
    severity: str | None,
    *,
    title: str | None,
    description: str | None,
) -> bool:
    if severity == "CRITICAL":
        return False
    haystack = " ".join(part for part in (title, description) if part).lower()
    if not haystack:
        return False
    return bool(re.search(r"\bdenial of service\b|\bdos\b", haystack))
