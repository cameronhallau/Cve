from __future__ import annotations

from datetime import UTC, datetime

from cve_service.models.enums import AIReviewOutcome, ClassificationOutcome, CveState
from cve_service.services.ai_review import (
    AIProviderRequest,
    AIProviderResponse,
    build_ai_review_input_pack,
    determine_ai_review_route,
    execute_ai_review,
    validate_ai_response,
)
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record


class StaticProvider:
    def __init__(self, payload: dict[str, object] | str, *, model_name: str = "mock-gpt") -> None:
        self.payload = payload
        self.model_name = model_name
        self.requests: list[AIProviderRequest] = []

    def review(self, request: AIProviderRequest) -> AIProviderResponse:
        self.requests.append(request)
        return AIProviderResponse(model_name=self.model_name, payload=self.payload)


def test_validate_ai_response_rejects_invalid_json_text() -> None:
    validation = validate_ai_response("CVE-2026-0300", "{not-json")

    assert validation.schema_valid is False
    assert validation.outcome is AIReviewOutcome.INVALID
    assert validation.advisory_payload == {}
    assert validation.validation_errors[0].startswith("invalid_json:")


def test_validate_ai_response_rejects_schema_mismatch() -> None:
    validation = validate_ai_response(
        "CVE-2026-0301",
        {
            "cve_id": "CVE-2026-0301",
            "enterprise_relevance_assessment": "enterprise_relevant",
            "confidence": 0.9,
            "reasoning_summary": "missing exploit path",
        },
    )

    assert validation.schema_valid is False
    assert validation.outcome is AIReviewOutcome.INVALID
    assert validation.validation_errors == ("'exploit_path_assessment' is a required property",)


def test_execute_ai_review_skips_non_ambiguous_candidate(session_factory) -> None:
    provider = StaticProvider(
        {
            "cve_id": "CVE-2026-0302",
            "enterprise_relevance_assessment": "enterprise_relevant",
            "exploit_path_assessment": "internet_exploitable",
            "confidence": 0.94,
            "reasoning_summary": "Should never be used.",
        }
    )

    from cve_service.core.db import session_scope

    with session_scope(session_factory) as session:
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-0302",
                title="Exchange Server RCE",
                description="Critical Exchange issue.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 2, 18, 0, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
        )
        route = determine_ai_review_route(session, "CVE-2026-0302")
        result = execute_ai_review(session, "CVE-2026-0302", provider)

    assert route.should_route is False
    assert route.classification_outcome is ClassificationOutcome.CANDIDATE
    assert result.skipped is True
    assert result.review_attempted is False
    assert result.route_reason == "deterministic_non_ambiguous"
    assert result.state is CveState.POLICY_PENDING
    assert provider.requests == []


def test_build_ai_review_input_pack_uses_phase3_contract(session_factory) -> None:
    from cve_service.core.db import session_scope

    with session_scope(session_factory) as session:
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-0303",
                title="Widget Gateway issue",
                description="Ambiguous enterprise relevance.",
                severity="HIGH",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 2, 18, 15, tzinfo=UTC),
                vendor_name="Acme",
                product_name="Widget Gateway",
            ),
        )
        request_pack = build_ai_review_input_pack(session, "CVE-2026-0303")

    assert request_pack["schema_version"] == "phase3-ai-review-request.v1"
    assert request_pack["deterministic"]["outcome"] == "NEEDS_AI"
    assert request_pack["deterministic"]["ai_route"] == {
        "eligible": True,
        "allowed": True,
        "blocked_reason": None,
    }
