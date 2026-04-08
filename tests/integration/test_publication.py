from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, PolicyDecision, PublicationEvent
from cve_service.models.enums import CveState, EvidenceSignal, EvidenceStatus, PublicationEventStatus
from cve_service.services.description_compression import DescriptionCompressionResult
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publication import publish_initial_publication
from cve_service.services.publish_targets import ConsolePublishTarget, InMemoryPublishTarget


class PublishableProvider:
    def review(self, request):
        from cve_service.services.ai_review import AIProviderResponse

        return AIProviderResponse(
            model_name="mock-gpt",
            payload={
                "cve_id": request.request_payload["cve_id"],
                "enterprise_relevance_assessment": "enterprise_relevant",
                "exploit_path_assessment": "internet_exploitable",
                "confidence": 0.96,
                "reasoning_summary": "Publishable in enterprise deployments.",
            },
        )


class ScriptedDescriptionCompressor:
    def __init__(self, *outputs: str) -> None:
        self.outputs = list(outputs)
        self.calls = 0

    def compress(self, request) -> DescriptionCompressionResult:
        self.calls += 1
        text = self.outputs[min(self.calls - 1, len(self.outputs) - 1)]
        return DescriptionCompressionResult(
            compressed_description=text,
            source="llm",
            model_name="mock-compressor",
            prompt_version="phase9-description-compression.v1",
        )


def test_publish_service_moves_publish_pending_candidate_to_published_with_replay_snapshot(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-0800")

        target = InMemoryPublishTarget(name="test-memory")
        result = publish_initial_publication(
            session,
            "CVE-2026-0800",
            target,
            attempted_at=datetime(2026, 4, 2, 23, 0, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0800"))
        event = session.scalar(select(PublicationEvent))
        decision = session.scalar(select(PolicyDecision))
        audit_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.event_type.in_(("publication.succeeded",)))
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    assert result.published is True
    assert result.duplicate_blocked is False
    assert result.event_status is PublicationEventStatus.PUBLISHED
    assert result.attempt_count == 1
    assert cve is not None
    assert cve.state is CveState.PUBLISHED
    assert event is not None
    assert decision is not None
    assert event.destination == "test-memory"
    assert event.status is PublicationEventStatus.PUBLISHED
    assert event.policy_snapshot_id == decision.policy_snapshot_id
    assert event.payload_snapshot["schema_version"] == "phase4-publication-event.v1"
    assert event.payload_snapshot["publish_content"]["title"] == "CVE-2026-0800: Exchange Server RCE"
    assert event.payload_snapshot["replay_context"]["policy_decision"]["decision"] == "PUBLISH"
    assert event.payload_snapshot["replay_context"]["policy_decision"]["policy_snapshot_id"] == str(decision.policy_snapshot_id)
    assert event.payload_snapshot["replay_context"]["policy_configuration"]["id"] == str(decision.policy_snapshot_id)
    assert event.payload_snapshot["replay_context"]["policy_configuration"]["snapshot"]["policy_version"] == decision.policy_version
    assert event.payload_snapshot["attempts"][0]["outcome"] == "PUBLISHED"
    assert len(target.published_requests) == 1
    assert len(audit_events) == 1


def test_publish_service_blocks_duplicate_initial_publication_by_state_and_hash(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-0801")

        target = InMemoryPublishTarget(name="dup-memory")
        first = publish_initial_publication(session, "CVE-2026-0801", target)
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0801"))
        assert cve is not None
        cve.state = CveState.PUBLISH_PENDING
        session.flush()

        second = publish_initial_publication(session, "CVE-2026-0801", target)
        events = session.scalars(select(PublicationEvent)).all()

    assert first.published is True
    assert second.published is True
    assert second.duplicate_blocked is True
    assert second.event_id == first.event_id
    assert second.content_hash == first.content_hash
    assert len(events) == 1
    assert len(target.published_requests) == 1


def test_publish_service_retries_failed_attempts_without_duplicate_events(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-0802")

        target = InMemoryPublishTarget(name="retry-memory", failures_before_success=1)
        first = publish_initial_publication(session, "CVE-2026-0802", target)
        second = publish_initial_publication(session, "CVE-2026-0802", target)
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0802"))
        events = session.scalars(select(PublicationEvent)).all()

    assert first.published is False
    assert first.event_status is PublicationEventStatus.FAILED
    assert first.attempt_count == 1
    assert second.published is True
    assert second.event_id == first.event_id
    assert second.reused_event is True
    assert second.attempt_count == 2
    assert cve is not None
    assert cve.state is CveState.PUBLISHED
    assert len(events) == 1
    assert events[0].payload_snapshot["attempts"][0]["outcome"] == "FAILED"
    assert events[0].payload_snapshot["attempts"][1]["outcome"] == "PUBLISHED"
    assert len(target.published_requests) == 1


def test_publish_service_reuses_stored_description_brief_across_retries(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-0805")

        target = InMemoryPublishTarget(name="retry-memory-desc", failures_before_success=1)
        compressor = ScriptedDescriptionCompressor(
            "In Exchange Server, an unauth attacker can trigger RCE.",
            "In Exchange Server, this should not replace the stored brief.",
        )

        first = publish_initial_publication(
            session,
            "CVE-2026-0805",
            target,
            description_compressor=compressor,
        )
        second = publish_initial_publication(
            session,
            "CVE-2026-0805",
            target,
            description_compressor=compressor,
        )
        events = session.scalars(select(PublicationEvent)).all()

    assert first.published is False
    assert second.published is True
    assert second.reused_event is True
    assert compressor.calls == 1
    assert len(events) == 1
    assert events[0].payload_snapshot["replay_context"]["description_compression"]["description_brief"] == (
        "In Exchange Server, an unauth attacker can trigger RCE."
    )


def test_publish_target_abstraction_is_swappable_without_changing_core_outcome(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-0803")
        _prepare_publish_pending_cve(session, "CVE-2026-0804")

        memory_result = publish_initial_publication(session, "CVE-2026-0803", InMemoryPublishTarget(name="memory-a"))
        console_result = publish_initial_publication(session, "CVE-2026-0804", ConsolePublishTarget(name="console-a"))

    assert memory_result.published is True
    assert console_result.published is True
    assert memory_result.event_status is PublicationEventStatus.PUBLISHED
    assert console_result.event_status is PublicationEventStatus.PUBLISHED
    assert memory_result.attempt_count == 1
    assert console_result.attempt_count == 1
    assert memory_result.state is CveState.PUBLISHED
    assert console_result.state is CveState.PUBLISHED


def _prepare_publish_pending_cve(session, cve_id: str) -> None:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 4 publication fixture.",
            severity="CRITICAL",
            source_name="fixture-feed",
            source_modified_at=datetime(2026, 4, 2, 22, 30, tzinfo=UTC),
            vendor_name="Microsoft",
            product_name="Exchange Server",
        ),
    )
    record_evidence(
        session,
        EvidenceInput(
            cve_id=cve_id,
            signal_type=EvidenceSignal.POC,
            status=EvidenceStatus.PRESENT,
            source_name="trusted-poc-db",
            source_record_id=f"poc-{cve_id.lower()}",
            collected_at=datetime(2026, 4, 2, 22, 35, tzinfo=UTC),
            evidence_timestamp=datetime(2026, 4, 2, 22, 35, tzinfo=UTC),
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=0.91,
            raw_payload={"fixture": cve_id},
        ),
    )
    result = process_post_enrichment_workflow(
        session,
        cve_id,
        PublishableProvider(),
        requested_at=datetime(2026, 4, 2, 22, 40, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 2, 22, 40, tzinfo=UTC),
    )
    assert result.state is CveState.PUBLISH_PENDING
