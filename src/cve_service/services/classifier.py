from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from cve_service.models.enums import ClassificationOutcome, CveState
from cve_service.services.reason_codes import REASON_CODE_REGISTRY_VERSION, validate_reason_codes

CLASSIFIER_VERSION = "deterministic-classifier.v1"
AI_BLOCK_REASON = "phase1_ai_out_of_scope"

ProductScope = Literal["enterprise", "consumer_only", "unknown"]


@dataclass(frozen=True, slots=True)
class CanonicalProduct:
    vendor_name: str
    product_name: str
    canonical_name: str
    scope: ProductScope
    matched_alias: str | None = None


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    outcome: ClassificationOutcome
    confidence: float
    reason_codes: tuple[str, ...]
    next_state: CveState
    ai_route_eligible: bool
    details: dict[str, object]


@dataclass(frozen=True, slots=True)
class ProductCatalogEntry:
    canonical_name: str
    scope: ProductScope
    vendor_aliases: tuple[str, ...]
    product_aliases: tuple[str, ...]


_PRODUCT_CATALOG: tuple[ProductCatalogEntry, ...] = (
    ProductCatalogEntry(
        canonical_name="microsoft:exchange-server",
        scope="enterprise",
        vendor_aliases=("microsoft",),
        product_aliases=("exchange server", "microsoft exchange server"),
    ),
    ProductCatalogEntry(
        canonical_name="cisco:adaptive-security-appliance",
        scope="enterprise",
        vendor_aliases=("cisco", "cisco systems"),
        product_aliases=("adaptive security appliance", "asa", "asa firewall"),
    ),
    ProductCatalogEntry(
        canonical_name="tp-link:archer-ax50",
        scope="consumer_only",
        vendor_aliases=("tp-link", "tp link"),
        product_aliases=("archer ax50", "archer ax50 router", "archer router ax50"),
    ),
    ProductCatalogEntry(
        canonical_name="netgear:nighthawk-r7000",
        scope="consumer_only",
        vendor_aliases=("netgear",),
        product_aliases=("nighthawk r7000", "nighthawk router r7000", "nighthawk router"),
    ),
)


def _normalize_text(value: str) -> str:
    collapsed = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return re.sub(r"\s+", " ", collapsed)


def _slugify(value: str) -> str:
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-"))


def normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().upper()


def canonicalize_product(vendor_name: str, product_name: str) -> CanonicalProduct:
    normalized_vendor = _normalize_text(vendor_name)
    normalized_product = _normalize_text(product_name)

    for entry in _PRODUCT_CATALOG:
        if normalized_vendor in entry.vendor_aliases and normalized_product in entry.product_aliases:
            return CanonicalProduct(
                vendor_name=vendor_name,
                product_name=product_name,
                canonical_name=entry.canonical_name,
                scope=entry.scope,
                matched_alias=normalized_product,
            )

    return CanonicalProduct(
        vendor_name=vendor_name,
        product_name=product_name,
        canonical_name=f"{_slugify(vendor_name)}:{_slugify(product_name)}",
        scope="unknown",
        matched_alias=None,
    )


def classify_record(severity: str | None, product: CanonicalProduct) -> ClassificationResult:
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
                "product_scope": product.scope,
                "canonical_name": product.canonical_name,
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
                "product_scope": product.scope,
                "canonical_name": product.canonical_name,
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
            reason_codes=tuple(reason_codes),
            next_state=CveState.SUPPRESSED,
            ai_route_eligible=True,
            details={
                "classifier_version": CLASSIFIER_VERSION,
                "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
                "product_scope": product.scope,
                "canonical_name": product.canonical_name,
                "severity": normalized_severity,
                "ai_route": {"eligible": True, "allowed": False, "blocked_reason": AI_BLOCK_REASON},
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
            "product_scope": product.scope,
            "canonical_name": product.canonical_name,
            "severity": normalized_severity,
            "ai_route": {"eligible": False, "allowed": False, "blocked_reason": None},
        },
    )
