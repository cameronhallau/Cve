from __future__ import annotations

from cve_service.models.enums import ClassificationOutcome, CveState
from cve_service.services.classifier import classify_record, canonicalize_product


def test_alias_variants_map_to_same_canonical_product_identity() -> None:
    primary = canonicalize_product("Microsoft", "Exchange Server")
    alias = canonicalize_product("Microsoft Corporation", "MS Exchange Server")

    assert primary.canonical_name == "microsoft:exchange-server"
    assert alias.canonical_name == primary.canonical_name
    assert alias.canonical_vendor_name == "Microsoft"
    assert alias.canonical_product_name == "Exchange Server"


def test_classifier_denies_consumer_only_products() -> None:
    product = canonicalize_product("TPLINK", "AX50 Wireless Router")

    result = classify_record("CRITICAL", product)

    assert result.outcome is ClassificationOutcome.DENY
    assert result.next_state is CveState.SUPPRESSED
    assert result.reason_codes == ("classifier.deny.consumer_only_product",)
    assert result.ai_route_eligible is False
    assert result.details["canonical_name"] == "tp-link:archer-ax50"


def test_classifier_fail_closes_ambiguous_products_before_ai() -> None:
    product = canonicalize_product("Acme", "Widget Gateway")

    result = classify_record("HIGH", product)

    assert result.outcome is ClassificationOutcome.NEEDS_AI
    assert result.next_state is CveState.CLASSIFIED
    assert result.ai_route_eligible is True
    assert result.details["ai_route"] == {
        "eligible": True,
        "allowed": True,
        "blocked_reason": None,
    }


def test_classifier_denies_non_critical_dos_before_enrichment() -> None:
    product = canonicalize_product("Juniper Networks", "Junos OS")

    result = classify_record(
        "HIGH",
        product,
        title="Junos OS denial of service issue",
        description="A denial of service in flowd lets remote attackers crash the process.",
    )

    assert result.outcome is ClassificationOutcome.DENY
    assert result.next_state is CveState.SUPPRESSED
    assert result.reason_codes == ("classifier.deny.non_critical_denial_of_service",)
    assert result.ai_route_eligible is False


def test_classifier_allows_critical_dos_to_continue() -> None:
    product = canonicalize_product("Juniper Networks", "Junos OS")

    result = classify_record(
        "CRITICAL",
        product,
        title="Junos OS denial of service issue",
        description="A denial of service in flowd lets remote attackers crash the process.",
    )

    assert result.outcome is ClassificationOutcome.NEEDS_AI
    assert result.next_state is CveState.CLASSIFIED
