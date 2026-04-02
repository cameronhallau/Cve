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
    PublicationEventType,
)
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publish_queue import RQPublishJobProducer
from cve_service.services.publication import publish_initial_publication
from cve_service.services.publish_targets import InMemoryPublishTarget


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


def test_material_update_candidate_auto_enqueues_and_preserves_lineage(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-auto-enqueue-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
        publish_target_behavior={
            "external_id": "inline-auto-enqueue-5300",
            "response_payload": {"channel": "phase5-auto"},
        },
    )

    with session_scope(session_factory) as session:
        baseline_event = _prepare_published_cve(session, "CVE-2026-5300", initial_signal=EvidenceSignal.POC)
        record_evidence(
            session,
            _update_evidence_input(
                "CVE-2026-5300",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-5300",
                collected_at=datetime(2026, 4, 3, 1, 0, tzinfo=UTC),
                is_authoritative=True,
                confidence=0.99,
            ),
            publish_producer=producer,
        )

        candidate = session.scalar(select(UpdateCandidate))
        candidate_id = candidate.id if candidate is not None else None
        baseline_event_id = baseline_event.id

    job_ids = queue.get_job_ids()
    assert len(job_ids) == 1

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job = queue.fetch_job(job_ids[0])
    assert job is not None
    job.refresh()

    try:
        assert job.return_value()["status"] == "processed"
        assert job.return_value()["publication_event_type"] == "UPDATE"
        assert job.return_value()["publication_status"] == "PUBLISHED"

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5300"))
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.cve_id == cve.id,
                    AuditEvent.event_type == "workflow.publish_enqueue_requested",
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()
            update_event = session.scalar(
                select(PublicationEvent)
                .where(PublicationEvent.cve_id == cve.id, PublicationEvent.event_type == PublicationEventType.UPDATE)
                .order_by(PublicationEvent.created_at.desc(), PublicationEvent.id.desc())
            )

        assert cve is not None
        assert cve.state is CveState.PUBLISHED
        assert candidate_id is not None
        assert len(enqueue_events) == 1
        assert enqueue_events[0].details["trigger"] == "update_candidate_detected"
        assert update_event is not None
        assert update_event.triggering_update_candidate_id == candidate_id
        assert update_event.baseline_publication_event_id == baseline_event_id
    finally:
        job.delete()
        redis_client.close()


def test_metadata_only_churn_does_not_auto_enqueue_update_delivery(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-auto-enqueue-skip-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
    )

    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5301", initial_signal=EvidenceSignal.POC)
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-5301",
                title="Exchange Server RCE",
                description="Phase 5 auto-enqueue fixture.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 3, 1, 5, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
            publish_producer=producer,
        )

    with session_scope(session_factory) as session:
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5301"))
        enqueue_events = session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.cve_id == cve.id,
                AuditEvent.event_type.in_(("workflow.publish_enqueue_requested", "workflow.publish_enqueue_reused")),
            )
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    try:
        assert cve is not None
        assert cve.state is CveState.PUBLISHED
        assert queue.get_job_ids() == []
        assert enqueue_events == []
    finally:
        redis_client.close()


def test_auto_enqueue_rerun_reuses_existing_update_job(session_factory, migrated_engine, redis_url: str) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-auto-enqueue-reuse-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
    )
    evidence_input = _update_evidence_input(
        "CVE-2026-5302",
        signal_type=EvidenceSignal.ITW,
        status=EvidenceStatus.PRESENT,
        source_type=EvidenceSourceType.KEV,
        source_name="cisa-kev",
        source_record_id="kev-cve-2026-5302",
        collected_at=datetime(2026, 4, 3, 1, 10, tzinfo=UTC),
        is_authoritative=True,
        confidence=0.99,
    )

    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5302", initial_signal=EvidenceSignal.POC)
        record_evidence(
            session,
            evidence_input,
            publish_producer=producer,
        )

    first_job_ids = queue.get_job_ids()
    assert len(first_job_ids) == 1

    with session_scope(session_factory) as session:
        record_evidence(
            session,
            evidence_input,
            publish_producer=producer,
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5302"))
        enqueue_events = session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.cve_id == cve.id,
                AuditEvent.event_type.in_(("workflow.publish_enqueue_requested", "workflow.publish_enqueue_reused")),
            )
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    try:
        assert queue.get_job_ids() == first_job_ids
        assert [event.event_type for event in enqueue_events] == [
            "workflow.publish_enqueue_requested",
            "workflow.publish_enqueue_reused",
        ]
        assert enqueue_events[0].details["job_id"] == enqueue_events[1].details["job_id"]
        assert enqueue_events[0].details["publication_event_type"] == "UPDATE"
    finally:
        redis_client.close()


def _prepare_published_cve(session, cve_id: str, *, initial_signal: EvidenceSignal) -> PublicationEvent:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 5 auto-enqueue fixture.",
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
        raw_payload={"fixture": cve_id, "signal_type": signal_type.value},
    )
