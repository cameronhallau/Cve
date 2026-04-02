from __future__ import annotations

from cve_service.models.enums import ClassificationOutcome, CveState
from cve_service.services.classifier import classify_record, canonicalize_product


def test_classifier_denies_consumer_only_products() -> None:
    product = canonicalize_product("TP-Link", "Archer AX50 Router")

    result = classify_record("CRITICAL", product)

    assert result.outcome is ClassificationOutcome.DENY
    assert result.next_state is CveState.SUPPRESSED
    assert result.reason_codes == ("classifier.deny.consumer_only_product",)
    assert result.ai_route_eligible is False


def test_classifier_fail_closes_ambiguous_products_before_ai() -> None:
    product = canonicalize_product("Acme", "Widget Gateway")

    result = classify_record("HIGH", product)

    assert result.outcome is ClassificationOutcome.NEEDS_AI
    assert result.next_state is CveState.SUPPRESSED
    assert result.ai_route_eligible is True
    assert result.details["ai_route"] == {
        "eligible": True,
        "allowed": False,
        "blocked_reason": "phase1_ai_out_of_scope",
    }
