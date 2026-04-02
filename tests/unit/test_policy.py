from __future__ import annotations

from cve_service.models.enums import AIReviewOutcome, ClassificationOutcome, EvidenceStatus, PolicyDecisionOutcome
from cve_service.services.policy import PolicyEvaluationInput, evaluate_policy_inputs


def test_policy_publishes_deterministic_candidate_with_itw_signal() -> None:
    result = evaluate_policy_inputs(
        PolicyEvaluationInput(
            cve_id="CVE-2026-0400",
            severity="CRITICAL",
            deterministic_outcome=ClassificationOutcome.CANDIDATE,
            deterministic_reason_codes=("classifier.candidate.enterprise_high_or_critical",),
            poc_status=EvidenceStatus.UNKNOWN,
            poc_confidence=None,
            itw_status=EvidenceStatus.PRESENT,
            itw_confidence=1.0,
            ai_review_outcome=None,
            ai_schema_valid=False,
            ai_advisory=None,
        )
    )

    assert result.decision is PolicyDecisionOutcome.PUBLISH
    assert result.reason_codes == ("policy.publish.enterprise_candidate_with_itw",)
    assert result.ai_fields_considered == ()


def test_policy_defers_ai_candidate_without_valid_review() -> None:
    result = evaluate_policy_inputs(
        PolicyEvaluationInput(
            cve_id="CVE-2026-0401",
            severity="HIGH",
            deterministic_outcome=ClassificationOutcome.NEEDS_AI,
            deterministic_reason_codes=("classifier.needs_ai.unknown_product_scope",),
            poc_status=EvidenceStatus.PRESENT,
            poc_confidence=0.9,
            itw_status=EvidenceStatus.UNKNOWN,
            itw_confidence=None,
            ai_review_outcome=None,
            ai_schema_valid=False,
            ai_advisory=None,
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.ai_review_required",)


def test_policy_uses_ai_only_for_allowed_fields_and_still_requires_evidence() -> None:
    result = evaluate_policy_inputs(
        PolicyEvaluationInput(
            cve_id="CVE-2026-0402",
            severity="HIGH",
            deterministic_outcome=ClassificationOutcome.NEEDS_AI,
            deterministic_reason_codes=("classifier.needs_ai.unknown_product_scope",),
            poc_status=EvidenceStatus.UNKNOWN,
            poc_confidence=None,
            itw_status=EvidenceStatus.UNKNOWN,
            itw_confidence=None,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory={
                "cve_id": "CVE-2026-0402",
                "enterprise_relevance_assessment": "enterprise_relevant",
                "exploit_path_assessment": "internet_exploitable",
                "confidence": 0.92,
                "reasoning_summary": "Likely internet reachable in enterprise deployments.",
            },
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.awaiting_exploit_evidence",)
    assert result.ai_fields_considered == (
        "enterprise_relevance_assessment",
        "exploit_path_assessment",
        "confidence",
    )


def test_policy_hard_deny_remains_absolute_even_with_publish_advisory() -> None:
    result = evaluate_policy_inputs(
        PolicyEvaluationInput(
            cve_id="CVE-2026-0403",
            severity="CRITICAL",
            deterministic_outcome=ClassificationOutcome.DENY,
            deterministic_reason_codes=("classifier.deny.consumer_only_product",),
            poc_status=EvidenceStatus.PRESENT,
            poc_confidence=0.95,
            itw_status=EvidenceStatus.PRESENT,
            itw_confidence=1.0,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory={
                "cve_id": "CVE-2026-0403",
                "enterprise_relevance_assessment": "enterprise_relevant",
                "exploit_path_assessment": "internet_exploitable",
                "confidence": 0.99,
                "reasoning_summary": "Irrelevant because deterministic deny is hard.",
            },
        )
    )

    assert result.decision is PolicyDecisionOutcome.SUPPRESS
    assert result.reason_codes == ("policy.suppress.hard_deterministic_deny",)
    assert result.ai_fields_considered == ()
