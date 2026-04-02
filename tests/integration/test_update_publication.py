from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from redis import Redis
from rq import Queue, SimpleWorker
from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, PublicationEvent, UpdateCandidate
from cve_service.models.enums import (
    CveState,
    EvidenceSignal,
    EvidenceSourceType,
    EvidenceStatus,
    PublicationEventStatus,
    PublicationEventType,
)
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publication import publish_initial_publication, publish_update_publication
from cve_service.services.publish_queue import RQPublishJobProducer
from cve_service.services.publish_targets import InMemoryPublishTarget


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


def test_poc_triggered_update_publication_uses_snapshot_and_persists_lineage(session_factory) -> None:
    with session_scope(session_factory) as session:
        initial_event = _prepare_published_cve(session, "CVE-2026-5200", initial_signal=EvidenceSignal.ITW)
        record_evidence(
            session,
            _update_evidence_input(
                "CVE-2026-5200",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_name="trusted-poc-db",
                source_record_id="poc-cve-2026-5200",
                collected_at=datetime(2026, 4, 3, 0, 15, tzinfo=UTC),
            ),
        )

        candidate = session.scalar(select(UpdateCandidate))
        target = InMemoryPublishTarget(name="update-memory-poc")
        result = publish_update_publication(
            session,
            "CVE-2026-5200",
            target,
            attempted_at=datetime(2026, 4, 3, 0, 16, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5200"))
        update_event = session.scalar(
            select(PublicationEvent)
            .where(PublicationEvent.cve_id == cve.id, PublicationEvent.event_type == PublicationEventType.UPDATE)
            .order_by(PublicationEvent.created_at.desc(), PublicationEvent.id.desc())
        )

    assert candidate is not None
    assert cve is not None
    assert result.event_type is PublicationEventType.UPDATE
    assert result.event_status is PublicationEventStatus.PUBLISHED
    assert cve.state is CveState.PUBLISHED
    assert len(target.published_requests) == 1
    assert target.published_requests[0].event_type == "UPDATE"
    assert target.published_requests[0].content.schema_version == "phase5-update-publication.v1"

    assert update_event is not None
    assert update_event.event_type is PublicationEventType.UPDATE
    assert update_event.triggering_update_candidate_id == candidate.id
    assert update_event.baseline_publication_event_id == initial_event.id
    assert update_event.payload_snapshot["publish_content"]["metadata"]["material_changes"][0]["field"] == "evidence.poc_status"
    assert update_event.payload_snapshot["replay_context"]["update_candidate"]["id"] == str(candidate.id)
    assert (
        update_event.payload_snapshot["replay_context"]["publication_lineage"]["baseline_publication_event_id"]
        == str(initial_event.id)
    )
    assert (
        update_event.payload_snapshot["replay_context"]["publication_lineage"]["lineage_root_publication_event_id"]
        == str(initial_event.id)
    )


def test_kev_backed_itw_update_publication_uses_stored_signal_snapshot(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5201", initial_signal=EvidenceSignal.POC)
        record_evidence(
            session,
            _update_evidence_input(
                "CVE-2026-5201",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-5201",
                collected_at=datetime(2026, 4, 3, 0, 20, tzinfo=UTC),
                is_authoritative=True,
                confidence=0.99,
            ),
        )

        target = InMemoryPublishTarget(name="update-memory-itw")
        result = publish_update_publication(
            session,
            "CVE-2026-5201",
            target,
            attempted_at=datetime(2026, 4, 3, 0, 21, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5201"))
        update_event = session.scalar(
            select(PublicationEvent)
            .where(PublicationEvent.cve_id == cve.id, PublicationEvent.event_type == PublicationEventType.UPDATE)
            .order_by(PublicationEvent.created_at.desc(), PublicationEvent.id.desc())
        )

    assert cve is not None
    assert update_event is not None
    assert result.published is True
    assert result.event_type is PublicationEventType.UPDATE
    assert cve.state is CveState.PUBLISHED
    assert target.published_requests[0].content.metadata["material_changes"][0]["field"] == "evidence.itw_status"
    assert target.published_requests[0].content.metadata["current_evidence"]["itw"]["selected_source_type"] == "KEV"
    assert "ITW=UNKNOWN (n/a)" in target.published_requests[0].content.body
    assert "ITW=PRESENT (0.99)" in target.published_requests[0].content.body
    assert update_event.payload_snapshot["publish_content"]["metadata"]["current_evidence"]["itw"]["selected_source_type"] == "KEV"


def test_duplicate_update_publication_is_blocked_on_rerun(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5202", initial_signal=EvidenceSignal.POC)
        record_evidence(
            session,
            _update_evidence_input(
                "CVE-2026-5202",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-5202",
                collected_at=datetime(2026, 4, 3, 0, 25, tzinfo=UTC),
                is_authoritative=True,
                confidence=0.99,
            ),
        )

        target = InMemoryPublishTarget(name="update-memory-dup")
        first = publish_update_publication(session, "CVE-2026-5202", target)
        second = publish_update_publication(session, "CVE-2026-5202", target)
        update_events = session.scalars(
            select(PublicationEvent)
            .where(PublicationEvent.event_type == PublicationEventType.UPDATE)
            .order_by(PublicationEvent.created_at.asc(), PublicationEvent.id.asc())
        ).all()

    assert first.published is True
    assert second.published is True
    assert second.duplicate_blocked is True
    assert second.event_id == first.event_id
    assert len(update_events) == 1
    assert len(target.published_requests) == 1


def test_metadata_only_churn_does_not_enqueue_update_delivery(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-update-skip-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
    )

    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5203", initial_signal=EvidenceSignal.POC)
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-5203",
                title="Exchange Server RCE",
                description="Phase 5 update publication fixture.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 3, 0, 30, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
        )
        job_id = producer.schedule(
            session,
            "CVE-2026-5203",
            trigger="manual_update_enqueue",
        )

    with session_scope(session_factory) as session:
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5203"))
        skip_event = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.event_type == "workflow.publish_enqueue_skipped", AuditEvent.cve_id == cve.id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        )

    try:
        assert cve is not None
        assert cve.state is CveState.PUBLISHED
        assert job_id is None
        assert queue.get_job_ids() == []
        assert skip_event is not None
        assert skip_event.details["skip_reason"] == "state_ineligible:PUBLISHED"
    finally:
        redis_client.close()


def test_update_publish_queue_reuses_job_and_worker_processes_update(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-update-worker-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
        publish_target_behavior={
            "external_id": "inline-update-5204",
            "response_payload": {"channel": "phase5-test"},
        },
    )

    with session_scope(session_factory) as session:
        baseline_event = _prepare_published_cve(session, "CVE-2026-5204", initial_signal=EvidenceSignal.POC)
        record_evidence(
            session,
            _update_evidence_input(
                "CVE-2026-5204",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-5204",
                collected_at=datetime(2026, 4, 3, 0, 35, tzinfo=UTC),
                is_authoritative=True,
                confidence=0.99,
            ),
        )
        candidate = session.scalar(select(UpdateCandidate).where(UpdateCandidate.cve_id == baseline_event.cve_id))
        candidate_id = candidate.id if candidate is not None else None
        baseline_event_id = baseline_event.id
        first_job_id = producer.schedule(
            session,
            "CVE-2026-5204",
            trigger="update_candidate_detected",
        )

    assert first_job_id is not None
    assert queue.get_job_ids() == [first_job_id]

    with session_scope(session_factory) as session:
        second_job_id = producer.schedule(
            session,
            "CVE-2026-5204",
            trigger="update_candidate_detected",
        )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job = queue.fetch_job(first_job_id)
    assert job is not None
    job.refresh()

    try:
        assert second_job_id == first_job_id
        assert job.return_value()["status"] == "processed"
        assert job.return_value()["publication_event_type"] == "UPDATE"
        assert job.return_value()["published"] is True
        assert job.return_value()["publication_status"] == "PUBLISHED"

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5204"))
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.cve_id == cve.id,
                    AuditEvent.event_type.in_(("workflow.publish_enqueue_requested", "workflow.publish_enqueue_reused")),
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()
            update_event = session.scalar(
                select(PublicationEvent)
                .where(PublicationEvent.cve_id == cve.id, PublicationEvent.event_type == PublicationEventType.UPDATE)
                .order_by(PublicationEvent.created_at.desc(), PublicationEvent.id.desc())
            )

        assert cve is not None
        assert update_event is not None
        assert cve.state is CveState.PUBLISHED
        assert enqueue_events[0].details["publication_event_type"] == "UPDATE"
        assert any(event.event_type == "workflow.publish_enqueue_reused" for event in enqueue_events)
        assert update_event.triggering_update_candidate_id == candidate_id
        assert update_event.baseline_publication_event_id == baseline_event_id
    finally:
        job.delete()
        redis_client.close()


def _prepare_published_cve(session, cve_id: str, *, initial_signal: EvidenceSignal) -> PublicationEvent:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 5 update publication fixture.",
            severity="CRITICAL",
            source_name="fixture-feed",
            source_modified_at=datetime(2026, 4, 2, 23, 0, tzinfo=UTC),
            vendor_name="Microsoft",
            product_name="Exchange Server",
        ),
    )
    record_evidence(session, _initial_evidence_input(cve_id, initial_signal))
    workflow_result = process_post_enrichment_workflow(
        session,
        cve_id,
        NeverCalledProvider(),
        requested_at=datetime(2026, 4, 2, 23, 10, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 2, 23, 10, tzinfo=UTC),
    )
    assert workflow_result.state is CveState.PUBLISH_PENDING

    publish_initial_publication(
        session,
        cve_id,
        InMemoryPublishTarget(name=f"phase5-initial-{cve_id.lower()}"),
        attempted_at=datetime(2026, 4, 2, 23, 20, tzinfo=UTC),
    )
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    assert cve is not None
    publication_event = session.scalar(
        select(PublicationEvent)
        .where(PublicationEvent.cve_id == cve.id)
        .order_by(PublicationEvent.published_at.desc(), PublicationEvent.id.desc())
    )
    assert publication_event is not None
    return publication_event


def _initial_evidence_input(cve_id: str, signal_type: EvidenceSignal) -> EvidenceInput:
    source_type = EvidenceSourceType.TRUSTED_POC if signal_type is EvidenceSignal.POC else EvidenceSourceType.TRUSTED_ITW
    source_name = "trusted-poc-db" if signal_type is EvidenceSignal.POC else "trusted-itw-db"
    source_record_id = f"{signal_type.value.lower()}-{cve_id.lower()}"
    return _update_evidence_input(
        cve_id,
        signal_type=signal_type,
        status=EvidenceStatus.PRESENT,
        source_type=source_type,
        source_name=source_name,
        source_record_id=source_record_id,
        collected_at=datetime(2026, 4, 2, 23, 5, tzinfo=UTC),
        confidence=0.93,
    )


def _update_evidence_input(
    cve_id: str,
    *,
    signal_type: EvidenceSignal,
    status: EvidenceStatus,
    source_type: EvidenceSourceType,
    source_name: str,
    source_record_id: str,
    collected_at: datetime,
    confidence: float = 0.95,
    is_authoritative: bool = False,
) -> EvidenceInput:
    return EvidenceInput(
        cve_id=cve_id,
        signal_type=signal_type,
        status=status,
        source_type=source_type,
        source_name=source_name,
        source_record_id=source_record_id,
        evidence_timestamp=collected_at,
        collected_at=collected_at,
        freshness_ttl_seconds=14 * 24 * 60 * 60,
        confidence=confidence,
        is_authoritative=is_authoritative,
        raw_payload={"fixture": cve_id, "source_record_id": source_record_id},
    )
