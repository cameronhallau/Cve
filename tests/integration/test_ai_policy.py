from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AIReview, AuditEvent, CVE, PolicyDecision
from cve_service.models.enums import AIReviewOutcome, ClassificationOutcome, CveState, EvidenceSignal, EvidenceStatus, PolicyDecisionOutcome
from cve_service.services.ai_review import AIProviderRequest, AIProviderResponse, execute_ai_review, fingerprint_payload
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.policy import PolicyRuntimeConfig, apply_policy_gate


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
    assert cve.state is CveState.DEFERRED
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
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0501",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0501",
                evidence_timestamp=datetime(2026, 4, 2, 19, 5, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 19, 5, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.93,
                raw_payload={"origin": "fixture"},
            ),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0501"))
        assert cve is not None
        review = AIReview(
            cve_id=cve.id,
            model_name="mock-gpt",
            prompt_version="phase3-ai-review.v1",
            request_fingerprint=fingerprint_payload({"fixture": "hard-deny"}),
            request_payload={"fixture": "hard-deny"},
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

        gate = apply_policy_gate(
            session,
            "CVE-2026-0501",
            policy_version="phase4-policy.v9",
            policy_config=PolicyRuntimeConfig(ai_confidence_threshold=0.99),
        )
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
    assert decision.policy_version == "phase4-policy.v9"
    assert decision.policy_snapshot_id == gate.policy_snapshot_id
    assert decision.inputs_snapshot["ai_advisory_fields_considered"] == []
    assert decision.inputs_snapshot["policy_configuration"]["policy_version"] == "phase4-policy.v9"
    assert decision.conflict_resolution["has_conflict"] is True
    assert {conflict["type"] for conflict in decision.conflict_resolution["conflicts"]} >= {"deterministic_vs_ai", "deterministic_vs_evidence"}
    assert decision.rationale["outcome"] == "SUPPRESS"


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
    assert gate.reason_codes == ("policy.publish.ai_confirmed_initial_access_path",)
    assert cve is not None
    assert cve.state is CveState.PUBLISH_PENDING
    assert decision is not None
    assert decision.policy_snapshot_id == gate.policy_snapshot_id
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
    assert decision.inputs_snapshot["policy_configuration"]["snapshot"]["thresholds"]["ai_confidence_threshold"] == 0.75
    assert decision.rationale["outcome"] == "PUBLISH"
    assert decision.conflict_resolution["selected_outcome"] == "PUBLISH"
    assert sorted(event.event_type for event in audit_events if event.event_type.startswith("ai_review") or event.event_type.startswith("policy.")) == [
        "ai_review.persisted",
        "policy.decision_made",
    ]


def test_policy_reuse_stays_deterministic_for_same_policy_snapshot(session_factory) -> None:
    provider = StaticProvider(
        {
            "cve_id": "CVE-2026-0503",
            "enterprise_relevance_assessment": "enterprise_relevant",
            "exploit_path_assessment": "internet_exploitable",
            "confidence": 0.91,
            "reasoning_summary": "Publishable with enterprise relevance and exploit path.",
        }
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0503"))
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0503",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0503",
                evidence_timestamp=datetime(2026, 4, 2, 19, 15, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 19, 15, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.88,
                raw_payload={"origin": "fixture"},
            ),
        )
        execute_ai_review(session, "CVE-2026-0503", provider)

        first = apply_policy_gate(
            session,
            "CVE-2026-0503",
            evaluated_at=datetime(2026, 4, 2, 19, 20, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0503"))
        assert cve is not None
        cve.state = CveState.AI_REVIEW_PENDING
        session.flush()

        second = apply_policy_gate(
            session,
            "CVE-2026-0503",
            evaluated_at=datetime(2026, 4, 2, 20, 20, tzinfo=UTC),
        )

    assert first.decision is PolicyDecisionOutcome.PUBLISH
    assert second.decision is PolicyDecisionOutcome.PUBLISH
    assert second.reused is True
    assert second.decision_id == first.decision_id
    assert second.policy_snapshot_id == first.policy_snapshot_id


def test_policy_config_change_produces_new_explainable_outcome(session_factory) -> None:
    provider = StaticProvider(
        {
            "cve_id": "CVE-2026-0504",
            "enterprise_relevance_assessment": "enterprise_relevant",
            "exploit_path_assessment": "internet_exploitable",
            "confidence": 0.78,
            "reasoning_summary": "Borderline confidence that should be controlled by policy config.",
        }
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0504"))
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0504",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0504",
                evidence_timestamp=datetime(2026, 4, 2, 19, 25, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 19, 25, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.9,
                raw_payload={"origin": "fixture"},
            ),
        )
        execute_ai_review(session, "CVE-2026-0504", provider)

        baseline = apply_policy_gate(
            session,
            "CVE-2026-0504",
            evaluated_at=datetime(2026, 4, 2, 19, 30, tzinfo=UTC),
        )
        baseline_decision = session.get(PolicyDecision, baseline.decision_id)
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0504"))
        assert cve is not None
        cve.state = CveState.AI_REVIEW_PENDING
        session.flush()

        stricter = apply_policy_gate(
            session,
            "CVE-2026-0504",
            evaluated_at=datetime(2026, 4, 2, 19, 35, tzinfo=UTC),
            policy_version="phase4-policy.v2",
            policy_config=PolicyRuntimeConfig(ai_confidence_threshold=0.85),
        )
        stricter_decision = session.get(PolicyDecision, stricter.decision_id)

    assert baseline.decision is PolicyDecisionOutcome.PUBLISH
    assert stricter.decision is PolicyDecisionOutcome.DEFER
    assert stricter.reused is False
    assert baseline.decision_id != stricter.decision_id
    assert baseline.policy_snapshot_id != stricter.policy_snapshot_id
    assert baseline_decision is not None
    assert stricter_decision is not None
    assert baseline_decision.inputs_snapshot["policy_configuration"]["snapshot"]["thresholds"]["ai_confidence_threshold"] == 0.75
    assert stricter_decision.inputs_snapshot["policy_configuration"]["snapshot"]["thresholds"]["ai_confidence_threshold"] == 0.85
    assert stricter_decision.reason_codes == ["policy.defer.ai_low_confidence"]
    assert stricter_decision.rationale["summary"] == "AI advisory confidence is below the configured threshold, so policy fails closed."
    assert stricter_decision.conflict_resolution["selected_outcome"] == "DEFER"


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
