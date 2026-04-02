from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AIReview, AuditEvent, CVE, PolicyDecision
from cve_service.models.enums import AIReviewOutcome, ClassificationOutcome, CveState, EvidenceSignal, EvidenceStatus, PolicyDecisionOutcome
from cve_service.services.ai_review import AIProviderRequest, AIProviderResponse, execute_ai_review
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.policy import apply_policy_gate


class StaticProvider:
    def __init__(self, payload: dict[str, object] | str, *, model_name: str = "mock-gpt") -> None:
        self.payload = payload
        self.model_name = model_name
        self.requests: list[AIProviderRequest] = []

    def review(self, request: AIProviderRequest) -> AIProviderResponse:
        self.requests.append(request)
        return AIProviderResponse(model_name=self.model_name, payload=self.payload)


def test_invalid_ai_json_is_rejected_and_does_not_advance_state(session_factory) -> None:
    provider = StaticProvider("{not-json")

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0500"))

        result = execute_ai_review(session, "CVE-2026-0500", provider)
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0500"))
        reviews = session.scalars(select(AIReview)).all()
        decisions = session.scalars(select(PolicyDecision)).all()

    assert result.review_attempted is True
    assert result.schema_valid is False
    assert result.outcome is AIReviewOutcome.INVALID
    assert cve is not None
    assert cve.state is CveState.SUPPRESSED
    assert len(reviews) == 1
    assert reviews[0].schema_valid is False
    assert reviews[0].outcome is AIReviewOutcome.INVALID
    assert decisions == []


def test_hard_deny_cannot_be_overridden_by_ai_or_policy(session_factory) -> None:
    with session_scope(session_factory) as session:
        result = ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-0501",
                title="Consumer router issue",
                description="Critical router issue.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 2, 19, 0, tzinfo=UTC),
                vendor_name="TPLINK",
                product_name="AX50 Wireless Router",
            ),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0501"))
        assert cve is not None
        review = AIReview(
            cve_id=cve.id,
            model_name="mock-gpt",
            prompt_version="phase3-ai-review.v1",
            outcome=AIReviewOutcome.ADVISORY_PUBLISH,
            schema_valid=True,
            advisory_payload={
                "cve_id": "CVE-2026-0501",
                "enterprise_relevance_assessment": "enterprise_relevant",
                "exploit_path_assessment": "internet_exploitable",
                "confidence": 0.99,
                "reasoning_summary": "Incorrectly optimistic AI advisory.",
            },
            raw_response={
                "provider_payload": {
                    "cve_id": "CVE-2026-0501",
                    "enterprise_relevance_assessment": "enterprise_relevant",
                    "exploit_path_assessment": "internet_exploitable",
                    "confidence": 0.99,
                    "reasoning_summary": "Incorrectly optimistic AI advisory.",
                },
                "validation_errors": [],
            },
        )
        session.add(review)
        session.flush()

        gate = apply_policy_gate(session, "CVE-2026-0501")
        stored_cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0501"))
        decision = session.get(PolicyDecision, gate.decision_id)

    assert result.state is CveState.SUPPRESSED
    assert gate.decision is PolicyDecisionOutcome.SUPPRESS
    assert gate.reason_codes == ("policy.suppress.hard_deterministic_deny",)
    assert stored_cve is not None
    assert stored_cve.state is CveState.SUPPRESSED
    assert stored_cve.last_policy_outcome is PolicyDecisionOutcome.SUPPRESS
    assert decision is not None
    assert decision.deterministic_outcome is ClassificationOutcome.DENY
    assert decision.inputs_snapshot["ai_advisory_fields_considered"] == []


def test_ai_advisory_can_influence_allowed_policy_fields_with_replayable_snapshot(session_factory) -> None:
    provider = StaticProvider(
        {
            "cve_id": "CVE-2026-0502",
            "enterprise_relevance_assessment": "enterprise_relevant",
            "exploit_path_assessment": "internet_exploitable",
            "confidence": 0.91,
            "reasoning_summary": "Relevant for enterprise edge deployments with a direct exploit path.",
        }
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0502"))
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0502",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0502",
                evidence_timestamp=datetime(2026, 4, 2, 19, 10, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 19, 10, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.9,
                raw_payload={"origin": "fixture"},
            ),
        )

        review_result = execute_ai_review(session, "CVE-2026-0502", provider)
        gate = apply_policy_gate(session, "CVE-2026-0502")
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0502"))
        decision = session.get(PolicyDecision, gate.decision_id)
        audit_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.cve_id == cve.id)
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    assert review_result.schema_valid is True
    assert review_result.outcome is AIReviewOutcome.ADVISORY_PUBLISH
    assert gate.decision is PolicyDecisionOutcome.PUBLISH
    assert gate.reason_codes == ("policy.publish.ai_confirmed_with_poc",)
    assert cve is not None
    assert cve.state is CveState.PUBLISH_PENDING
    assert decision is not None
    assert decision.inputs_snapshot["evidence"] == {
        "poc_status": "PRESENT",
        "poc_confidence": 0.9,
        "itw_status": "UNKNOWN",
        "itw_confidence": None,
    }
    assert decision.inputs_snapshot["ai_advisory_fields_considered"] == [
        "enterprise_relevance_assessment",
        "exploit_path_assessment",
        "confidence",
    ]
    assert decision.inputs_snapshot["ai_review"]["schema_valid"] is True
    assert decision.inputs_snapshot["ai_review"]["advisory_payload"]["enterprise_relevance_assessment"] == "enterprise_relevant"
    assert sorted(event.event_type for event in audit_events if event.event_type.startswith("ai_review") or event.event_type.startswith("policy.")) == [
        "ai_review.persisted",
        "policy.decision_made",
    ]


def _ambiguous_record(cve_id: str) -> PublicFeedRecord:
    return PublicFeedRecord(
        cve_id=cve_id,
        title="Widget Gateway issue",
        description="High severity issue in an ambiguous gateway line.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 19, 0, tzinfo=UTC),
        vendor_name="Acme",
        product_name="Widget Gateway",
    )
