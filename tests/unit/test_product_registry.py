from __future__ import annotations

from cve_service.services.product_registry import PRODUCT_REGISTRY_VERSION, canonicalize_product


def test_registry_resolves_aliases_to_stable_canonical_identity() -> None:
    resolved = canonicalize_product("Microsoft Corporation", "MS Exchange Server")

    assert PRODUCT_REGISTRY_VERSION == "product-registry.v1"
    assert resolved.canonical_name == "microsoft:exchange-server"
    assert resolved.canonical_vendor_name == "Microsoft"
    assert resolved.canonical_product_name == "Exchange Server"
    assert resolved.matched_vendor_alias == "microsoft corporation"
    assert resolved.matched_product_alias == "ms exchange server"


def test_registry_falls_back_to_unknown_identity_for_unlisted_products() -> None:
    resolved = canonicalize_product("Acme", "Widget Gateway")

    assert resolved.scope == "unknown"
    assert resolved.canonical_name == "acme:widget-gateway"
    assert resolved.matched_vendor_alias is None
    assert resolved.matched_product_alias is None
