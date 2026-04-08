from __future__ import annotations

from datetime import UTC, datetime

from cve_service.models.enums import AIReviewOutcome, ClassificationOutcome, EvidenceStatus, PolicyDecisionOutcome
from cve_service.services.policy import PolicyEvaluationInput, evaluate_policy_inputs


def test_policy_publishes_enterprise_candidate_with_ai_confirmed_initial_access_path() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0400",
            deterministic_outcome=ClassificationOutcome.CANDIDATE,
            deterministic_reason_codes=("classifier.candidate.enterprise_high_or_critical",),
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory("CVE-2026-0400", exploit_path="phishing_initial_access"),
        )
    )

    assert result.decision is PolicyDecisionOutcome.PUBLISH
    assert result.reason_codes == ("policy.publish.enterprise_candidate_with_initial_access_path",)
    assert result.ai_fields_considered == (
        "enterprise_relevance_assessment",
        "exploit_path_assessment",
        "confidence",
    )


def test_policy_defers_ai_candidate_without_valid_review() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0401",
            deterministic_outcome=ClassificationOutcome.NEEDS_AI,
            deterministic_reason_codes=("classifier.needs_ai.unknown_product_scope",),
            poc_status=EvidenceStatus.PRESENT,
            poc_confidence=0.9,
            ai_review_outcome=None,
            ai_schema_valid=False,
            ai_advisory=None,
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.ai_review_required",)


def test_policy_publishes_ai_candidate_without_waiting_for_evidence_when_initial_access_path_is_confirmed() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0402",
            deterministic_outcome=ClassificationOutcome.NEEDS_AI,
            deterministic_reason_codes=("classifier.needs_ai.unknown_product_scope",),
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory("CVE-2026-0402"),
        )
    )

    assert result.decision is PolicyDecisionOutcome.PUBLISH
    assert result.reason_codes == ("policy.publish.ai_confirmed_initial_access_path",)
    assert result.ai_fields_considered == (
        "enterprise_relevance_assessment",
        "exploit_path_assessment",
        "confidence",
    )


def test_policy_hard_deny_remains_absolute_even_with_publish_advisory() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
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
            ai_advisory=_publishable_ai_advisory(
                "CVE-2026-0403",
                confidence=0.99,
                reasoning_summary="Irrelevant because deterministic deny is hard.",
            ),
        )
    )

    assert result.decision is PolicyDecisionOutcome.SUPPRESS
    assert result.reason_codes == ("policy.suppress.hard_deterministic_deny",)
    assert result.ai_fields_considered == ()


def test_policy_defers_publishable_ai_outcome_when_epss_score_is_too_low() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0404",
            poc_status=EvidenceStatus.PRESENT,
            poc_confidence=0.96,
            epss_score=0.0012,
            epss_percentile=0.04,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory(
                "CVE-2026-0404",
                reasoning_summary="Publishable on exploit path alone, absent a stronger external risk signal.",
            ),
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.low_epss_score",)
    assert result.rationale["external_enrichment"]["epss"] == {"score": 0.0012, "percentile": 0.04}


def test_policy_does_not_require_epss_for_publishable_ai_outcome() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0405",
            poc_status=EvidenceStatus.PRESENT,
            poc_confidence=0.96,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory(
                "CVE-2026-0405",
                reasoning_summary="Publishable without a cached EPSS signal.",
            ),
        )
    )

    assert result.decision is PolicyDecisionOutcome.PUBLISH
    assert result.reason_codes == ("policy.publish.ai_confirmed_initial_access_path",)
    assert result.rationale["external_enrichment"]["epss"] == {"score": None, "percentile": None}


def test_policy_allows_publishable_ai_outcome_when_epss_score_is_above_threshold() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0406",
            poc_status=EvidenceStatus.PRESENT,
            poc_confidence=0.96,
            epss_score=0.1001,
            epss_percentile=0.42,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory(
                "CVE-2026-0406",
                reasoning_summary="Publishable with an EPSS score above the threshold.",
            ),
        )
    )

    assert result.decision is PolicyDecisionOutcome.PUBLISH
    assert result.reason_codes == ("policy.publish.ai_confirmed_initial_access_path",)
    assert result.rationale["external_enrichment"]["epss"] == {"score": 0.1001, "percentile": 0.42}


def test_policy_defers_stale_initial_publication_without_trusted_override() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0407",
            source_published_at=datetime(2026, 3, 1, 12, 0, tzinfo=UTC),
            evaluated_at=datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory("CVE-2026-0407"),
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.stale_initial_publication",)


def test_policy_allows_stale_initial_publication_with_trusted_override() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0408",
            source_published_at=datetime(2026, 3, 1, 12, 0, tzinfo=UTC),
            evaluated_at=datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
            kev_matched=True,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory("CVE-2026-0408"),
        )
    )

    assert result.decision is PolicyDecisionOutcome.PUBLISH
    assert result.reason_codes == ("policy.publish.ai_confirmed_initial_access_path",)


def test_policy_defers_publish_when_source_description_is_missing_and_no_override_exists() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0409",
            source_description=None,
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory("CVE-2026-0409"),
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.insufficient_source_description",)


def test_policy_defers_recent_similar_publication_bursts() -> None:
    result = evaluate_policy_inputs(
        _build_policy_input(
            cve_id="CVE-2026-0410",
            recent_similar_publication_ids=("event-1",),
            ai_review_outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            ai_schema_valid=True,
            ai_advisory=_publishable_ai_advisory("CVE-2026-0410"),
        )
    )

    assert result.decision is PolicyDecisionOutcome.DEFER
    assert result.reason_codes == ("policy.defer.recent_similar_publication",)


def _build_policy_input(
    *,
    cve_id: str,
    severity: str = "HIGH",
    title: str = "Widget Gateway remote code execution vulnerability",
    canonical_name: str = "acme:widget-gateway",
    source_description: str | None = (
        "Unauthenticated attackers can send crafted payloads to the widget gateway and execute code remotely."
    ),
    source_published_at: datetime | None = datetime(2026, 4, 2, 12, 0, tzinfo=UTC),
    source_modified_at: datetime | None = datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
    evaluated_at: datetime = datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
    deterministic_outcome: ClassificationOutcome = ClassificationOutcome.NEEDS_AI,
    deterministic_reason_codes: tuple[str, ...] = ("classifier.needs_ai.unknown_product_scope",),
    poc_status: EvidenceStatus = EvidenceStatus.UNKNOWN,
    poc_confidence: float | None = None,
    itw_status: EvidenceStatus = EvidenceStatus.UNKNOWN,
    itw_confidence: float | None = None,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
    kev_matched: bool = False,
    recent_similar_publication_ids: tuple[str, ...] = (),
    ai_review_outcome: AIReviewOutcome | None = None,
    ai_schema_valid: bool = False,
    ai_advisory: dict[str, object] | None = None,
) -> PolicyEvaluationInput:
    return PolicyEvaluationInput(
        cve_id=cve_id,
        title=title,
        severity=severity,
        canonical_name=canonical_name,
        source_description=source_description,
        source_published_at=source_published_at,
        source_modified_at=source_modified_at,
        evaluated_at=evaluated_at,
        deterministic_outcome=deterministic_outcome,
        deterministic_reason_codes=deterministic_reason_codes,
        poc_status=poc_status,
        poc_confidence=poc_confidence,
        itw_status=itw_status,
        itw_confidence=itw_confidence,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_matched=kev_matched,
        recent_similar_publication_ids=recent_similar_publication_ids,
        ai_review_outcome=ai_review_outcome,
        ai_schema_valid=ai_schema_valid,
        ai_advisory=ai_advisory,
    )


def _publishable_ai_advisory(
    cve_id: str,
    *,
    exploit_path: str = "internet_exploitable",
    confidence: float = 0.94,
    reasoning_summary: str = "Relevant for enterprise edge deployments with a direct exploit path.",
) -> dict[str, object]:
    return {
        "cve_id": cve_id,
        "enterprise_relevance_assessment": "enterprise_relevant",
        "exploit_path_assessment": exploit_path,
        "confidence": confidence,
        "reasoning_summary": reasoning_summary,
    }
