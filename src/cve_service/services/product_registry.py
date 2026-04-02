from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ProductScope = Literal["enterprise", "consumer_only", "unknown"]
PRODUCT_REGISTRY_VERSION = "product-registry.v1"


@dataclass(frozen=True, slots=True)
class CanonicalProduct:
    vendor_name: str
    product_name: str
    canonical_vendor_name: str
    canonical_product_name: str
    canonical_name: str
    scope: ProductScope
    matched_vendor_alias: str | None = None
    matched_product_alias: str | None = None


@dataclass(frozen=True, slots=True)
class ProductCatalogEntry:
    canonical_vendor_name: str
    canonical_product_name: str
    canonical_name: str
    scope: ProductScope
    vendor_aliases: tuple[str, ...]
    product_aliases: tuple[str, ...]


PRODUCT_CATALOG: tuple[ProductCatalogEntry, ...] = (
    ProductCatalogEntry(
        canonical_vendor_name="Microsoft",
        canonical_product_name="Exchange Server",
        canonical_name="microsoft:exchange-server",
        scope="enterprise",
        vendor_aliases=("microsoft", "ms", "microsoft corporation"),
        product_aliases=(
            "exchange server",
            "microsoft exchange server",
            "exchange",
            "ms exchange server",
        ),
    ),
    ProductCatalogEntry(
        canonical_vendor_name="Cisco",
        canonical_product_name="Adaptive Security Appliance",
        canonical_name="cisco:adaptive-security-appliance",
        scope="enterprise",
        vendor_aliases=("cisco", "cisco systems"),
        product_aliases=(
            "adaptive security appliance",
            "asa",
            "asa firewall",
            "cisco asa",
            "cisco adaptive security appliance",
        ),
    ),
    ProductCatalogEntry(
        canonical_vendor_name="TP-Link",
        canonical_product_name="Archer AX50",
        canonical_name="tp-link:archer-ax50",
        scope="consumer_only",
        vendor_aliases=("tp-link", "tp link", "tplink"),
        product_aliases=(
            "archer ax50",
            "archer ax50 router",
            "archer router ax50",
            "ax50 wireless router",
            "tp link archer ax50",
        ),
    ),
    ProductCatalogEntry(
        canonical_vendor_name="Netgear",
        canonical_product_name="Nighthawk R7000",
        canonical_name="netgear:nighthawk-r7000",
        scope="consumer_only",
        vendor_aliases=("netgear",),
        product_aliases=("nighthawk r7000", "nighthawk router r7000", "nighthawk router"),
    ),
)


def canonicalize_product(vendor_name: str, product_name: str) -> CanonicalProduct:
    normalized_vendor = _normalize_text(vendor_name)
    normalized_product = _normalize_text(product_name)

    for entry in PRODUCT_CATALOG:
        matched_vendor_alias = _best_matching_alias(normalized_vendor, entry.vendor_aliases)
        matched_product_alias = _best_matching_alias(normalized_product, entry.product_aliases)
        if matched_vendor_alias is not None and matched_product_alias is not None:
            return CanonicalProduct(
                vendor_name=vendor_name,
                product_name=product_name,
                canonical_vendor_name=entry.canonical_vendor_name,
                canonical_product_name=entry.canonical_product_name,
                canonical_name=entry.canonical_name,
                scope=entry.scope,
                matched_vendor_alias=matched_vendor_alias,
                matched_product_alias=matched_product_alias,
            )

    return CanonicalProduct(
        vendor_name=vendor_name,
        product_name=product_name,
        canonical_vendor_name=vendor_name,
        canonical_product_name=product_name,
        canonical_name=f"{_slugify(vendor_name)}:{_slugify(product_name)}",
        scope="unknown",
        matched_vendor_alias=None,
        matched_product_alias=None,
    )


def _normalize_text(value: str) -> str:
    collapsed = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return re.sub(r"\s+", " ", collapsed)


def _tokenize(value: str) -> tuple[str, ...]:
    normalized = _normalize_text(value)
    return tuple(token for token in normalized.split(" ") if token)


def _slugify(value: str) -> str:
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-"))


def _alias_matches(normalized_value: str, alias: str) -> bool:
    if normalized_value == alias:
        return True

    value_tokens = set(_tokenize(normalized_value))
    alias_tokens = set(_tokenize(alias))
    return bool(alias_tokens) and alias_tokens.issubset(value_tokens)


def _best_matching_alias(normalized_value: str, aliases: tuple[str, ...]) -> str | None:
    matches = [alias for alias in aliases if _alias_matches(normalized_value, alias)]
    if not matches:
        return None

    return max(matches, key=lambda alias: (len(_tokenize(alias)), len(alias)))
