from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from cve_service.models.entities import AIReview, CVE, Classification, PolicyDecision, UpdateCandidate
from cve_service.models.enums import (
    AIReviewOutcome,
    ClassificationOutcome,
    CveState,
    EvidenceSignal,
    EvidenceStatus,
    PolicyDecisionOutcome,
)
from cve_service.services.publish_content import build_initial_publish_content, build_update_publish_content
from cve_service.services.publication import prepare_initial_publication


def test_build_initial_publish_content_is_canonical_and_replayable() -> None:
    cve = CVE(
        id=uuid4(),
        cve_id="CVE-2026-0700",
        title="Exchange Server RCE",
        description="Remote code execution in Exchange Server.",
        severity="CRITICAL",
        state=CveState.PUBLISH_PENDING,
        poc_status=EvidenceStatus.PRESENT,
        poc_confidence=0.92,
        itw_status=EvidenceStatus.UNKNOWN,
        itw_confidence=None,
        external_enrichment={
            "sources": {
                "github_poc": {"status": "completed", "matched": True, "match_count": 2},
                "exploitdb": {"status": "completed", "matched": True, "match_count": 1},
                "epss": {"status": "completed", "score": 0.87, "percentile": 0.98},
            }
        },
    )
    classification = Classification(
        id=uuid4(),
        cve_id=cve.id,
        classifier_version="phase1-classifier.v1",
        outcome=ClassificationOutcome.CANDIDATE,
        reason_codes=["classifier.candidate.enterprise_high_or_critical"],
        details={
            "canonical_name": "microsoft:exchange_server",
            "product_scope": "enterprise",
        },
    )
    decision = PolicyDecision(
        id=uuid4(),
        cve_id=cve.id,
        policy_version="phase3-policy.v1",
        input_fingerprint="policy-fingerprint",
        decision=PolicyDecisionOutcome.PUBLISH,
        deterministic_outcome=ClassificationOutcome.CANDIDATE,
        reason_codes=["policy.publish.enterprise_candidate_with_poc"],
        inputs_snapshot={"fixture": True},
    )
    ai_review = AIReview(
        id=uuid4(),
        cve_id=cve.id,
        model_name="mock-gpt",
        prompt_version="phase3-ai-review.v1",
        request_fingerprint="request-fingerprint",
        request_payload={"fixture": True},
        outcome=AIReviewOutcome.ADVISORY_PUBLISH,
        schema_valid=True,
        advisory_payload={"confidence": 0.91},
        raw_response={"provider_payload": {"confidence": 0.91}},
    )

    content = build_initial_publish_content(
        cve=cve,
        classification=classification,
        decision=decision,
        ai_review=ai_review,
    )

    assert content.schema_version == "phase4-initial-publication.v1"
    assert content.title == "CVE-2026-0700: Exchange Server RCE"
    assert content.summary == "CRITICAL | microsoft:exchange_server | poc"
    assert "Policy Decision: PUBLISH" in content.body
    assert "External Enrichment: github_poc=match(2), exploitdb=match(1), epss=0.8700/0.98" in content.body
    assert "AI Advisory Used: yes" in content.body
    assert content.metadata["policy_reason_codes"] == ["policy.publish.enterprise_candidate_with_poc"]
    assert content.metadata["external_enrichment"]["sources"]["github_poc"]["match_count"] == 2
    assert content.as_payload()["labels"][0] == "severity:critical"


def test_build_update_publish_content_uses_stored_material_change_snapshot() -> None:
    candidate = UpdateCandidate(
        id=uuid4(),
        cve_id=uuid4(),
        publication_event_id=uuid4(),
        comparison_fingerprint="comparison-fingerprint",
        comparator_version="phase5-material-change-comparator.v1",
        reason_codes=["update.material.evidence_poc_status_changed"],
        comparison_snapshot={
            "baseline": {
                "publication": {"event_id": "baseline-event-1"},
                "cve": {
                    "cve_id": "CVE-2026-0702",
                    "severity": "CRITICAL",
                },
                "evidence": {
                    "poc": {"status": "UNKNOWN", "confidence": None},
                    "itw": {"status": "UNKNOWN", "confidence": None},
                },
            },
            "current": {
                "cve": {
                    "cve_id": "CVE-2026-0702",
                    "severity": "CRITICAL",
                },
                "classification": {
                    "canonical_name": "microsoft:exchange_server",
                    "product_scope": "enterprise",
                },
                "evidence": {
                    "poc": {"status": "PRESENT", "confidence": 0.97},
                    "itw": {"status": "UNKNOWN", "confidence": None},
                },
            },
            "changes": {
                "material": [
                    {
                        "field": "evidence.poc_status",
                        "before": "UNKNOWN",
                        "after": "PRESENT",
                        "explanation": "Proof-of-concept status changed relative to the last published state.",
                    }
                ]
            },
            "reason_codes": ["update.material.evidence_poc_status_changed"],
        },
    )

    content = build_update_publish_content(update_candidate=candidate)

    assert content.schema_version == "phase5-update-publication.v1"
    assert content.title == "CVE-2026-0702 Update: POC UNKNOWN -> PRESENT"
    assert content.summary == "CRITICAL | microsoft:exchange_server | poc:UNKNOWN->PRESENT"
    assert "Baseline Publication Event: baseline-event-1" in content.body
    assert "Current Evidence: PoC=PRESENT (0.97), ITW=UNKNOWN (n/a)" in content.body
    assert content.metadata["comparison_fingerprint"] == "comparison-fingerprint"
    assert content.metadata["baseline_publication_event_id"] == "baseline-event-1"
    assert "publication:update" in content.as_payload()["labels"]


def test_prepare_initial_publication_changes_idempotency_key_per_target(session_factory) -> None:
    from cve_service.core.db import session_scope
    from cve_service.services.enrichment import EvidenceInput, record_evidence
    from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
    from cve_service.services.post_enrichment import process_post_enrichment_workflow

    class NeverCalledProvider:
        def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
            raise AssertionError("AI should not be called for deterministic candidates")

    with session_scope(session_factory) as session:
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-0701",
                title="Exchange Server RCE",
                description="Remote code execution in Exchange Server.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 2, 22, 0, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
        )
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0701",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0701",
                collected_at=datetime(2026, 4, 2, 22, 5, tzinfo=UTC),
                evidence_timestamp=datetime(2026, 4, 2, 22, 5, tzinfo=UTC),
                freshness_ttl_seconds=86400,
                confidence=0.9,
            ),
        )
        process_post_enrichment_workflow(session, "CVE-2026-0701", NeverCalledProvider())

        console_prepared = prepare_initial_publication(session, "CVE-2026-0701", target_name="console")
        inline_prepared = prepare_initial_publication(session, "CVE-2026-0701", target_name="inline")

    assert console_prepared.content_hash == inline_prepared.content_hash
    assert console_prepared.idempotency_key != inline_prepared.idempotency_key
