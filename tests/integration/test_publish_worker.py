from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from redis import Redis
from rq import Queue, SimpleWorker
from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, PublicationEvent
from cve_service.models.enums import (
    CveState,
    EvidenceSignal,
    EvidenceStatus,
    PublicationEventStatus,
    PolicyDecisionOutcome,
)
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.policy import apply_policy_gate
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publish_queue import RQPublishJobProducer
from cve_service.workers.jobs import process_post_enrichment_workflow_job, process_publication_job


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


def test_post_enrichment_worker_hands_publishable_candidate_to_publication_job(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0900"))
        record_evidence(session, _poc_evidence_input("CVE-2026-0900", "poc-2026-0900"))

    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase4-handoff-{uuid4().hex}", connection=redis_client)
    workflow_job = queue.enqueue(
        process_post_enrichment_workflow_job,
        "CVE-2026-0900",
        migrated_engine.url.render_as_string(hide_password=False),
        ai_payload=_valid_ai_payload("CVE-2026-0900"),
        publish_target_name="inline",
        publish_target_behavior={
            "external_id": "inline-publication-0900",
            "response_payload": {"channel": "phase4-test"},
        },
        requested_at="2026-04-02T23:30:00+00:00",
        evaluated_at="2026-04-02T23:31:00+00:00",
    )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    workflow_job.refresh()
    publication_job = queue.fetch_job(workflow_job.return_value()["publication_job_id"])
    assert publication_job is not None
    publication_job.refresh()

    try:
        assert workflow_job.return_value()["status"] == "processed"
        assert workflow_job.return_value()["state"] == "PUBLISH_PENDING"
        assert workflow_job.return_value()["publication_job_id"] is not None
        assert publication_job.return_value()["status"] == "processed"
        assert publication_job.return_value()["published"] is True
        assert publication_job.return_value()["publication_status"] == "PUBLISHED"

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0900"))
            events = session.scalars(select(PublicationEvent)).all()
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_type == "workflow.publish_enqueue_requested")
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISHED
        assert len(events) == 1
        assert events[0].status is PublicationEventStatus.PUBLISHED
        assert len(enqueue_events) == 1
        assert enqueue_events[0].details["trigger"] == "policy_publish_handoff"
    finally:
        workflow_job.delete()
        if publication_job is not None:
            publication_job.delete()
        redis_client.close()


def test_publish_worker_retries_failed_attempts_without_duplicate_event_rows(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        _prepare_publish_pending_cve(session, "CVE-2026-0901")

    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase4-publish-{uuid4().hex}", connection=redis_client)
    first_job = queue.enqueue(
        process_publication_job,
        "CVE-2026-0901",
        migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
        publish_target_behavior={"fail_with": "temporary target outage"},
        attempted_at="2026-04-02T23:40:00+00:00",
    )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    first_job.refresh()

    second_job = queue.enqueue(
        process_publication_job,
        "CVE-2026-0901",
        migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
        publish_target_behavior={"external_id": "inline-publication-0901"},
        attempted_at="2026-04-02T23:45:00+00:00",
    )
    worker.work(burst=True)
    second_job.refresh()

    try:
        assert first_job.return_value()["status"] == "failed"
        assert first_job.return_value()["publication_status"] == "FAILED"
        assert second_job.return_value()["status"] == "processed"
        assert second_job.return_value()["publication_status"] == "PUBLISHED"
        assert second_job.return_value()["reused_event"] is True
        assert second_job.return_value()["attempt_count"] == 2

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0901"))
            events = session.scalars(select(PublicationEvent)).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISHED
        assert len(events) == 1
        assert events[0].attempt_count == 2
        assert [attempt["outcome"] for attempt in events[0].payload_snapshot["attempts"]] == ["FAILED", "PUBLISHED"]
    finally:
        first_job.delete()
        second_job.delete()
        redis_client.close()


def test_publish_queue_skips_suppressed_and_deferred_cases(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase4-publish-skip-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0902"))
        deferred_result = process_post_enrichment_workflow(
            session,
            "CVE-2026-0902",
            NeverCalledProvider(),
            requested_at=datetime(2026, 4, 2, 23, 50, tzinfo=UTC),
            evaluated_at=datetime(2026, 4, 2, 23, 50, tzinfo=UTC),
        )
        deferred_job_id = producer.schedule(
            session,
            "CVE-2026-0902",
            trigger="manual_phase4_check",
        )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _consumer_router_record("CVE-2026-0903"))
        suppress_gate = apply_policy_gate(session, "CVE-2026-0903")
        suppressed_job_id = producer.schedule(
            session,
            "CVE-2026-0903",
            trigger="manual_phase4_check",
        )

    with session_scope(session_factory) as session:
        skip_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.event_type == "workflow.publish_enqueue_skipped")
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    try:
        assert deferred_result.state is CveState.DEFERRED
        assert suppress_gate.decision is PolicyDecisionOutcome.SUPPRESS
        assert deferred_job_id is None
        assert suppressed_job_id is None
        assert queue.get_job_ids() == []
        assert len(skip_events) == 2
        assert skip_events[0].details["skip_reason"] == "no_publishable_policy_decision"
        assert skip_events[1].details["skip_reason"] == "no_publishable_policy_decision"
    finally:
        redis_client.close()


def _prepare_publish_pending_cve(session, cve_id: str) -> None:
    ingest_public_feed_record(session, _record(cve_id))
    record_evidence(session, _poc_evidence_input(cve_id, f"poc-{cve_id.lower()}"))
    result = process_post_enrichment_workflow(
        session,
        cve_id,
        NeverCalledProvider(),
        requested_at=datetime(2026, 4, 2, 23, 35, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 2, 23, 35, tzinfo=UTC),
    )
    assert result.state is CveState.PUBLISH_PENDING


def _record(cve_id: str) -> PublicFeedRecord:
    return PublicFeedRecord(
        cve_id=cve_id,
        title="Exchange Server RCE",
        description="Phase 4 publish worker fixture.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 23, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )


def _consumer_router_record(cve_id: str) -> PublicFeedRecord:
    return PublicFeedRecord(
        cve_id=cve_id,
        title="Consumer router issue",
        description="Critical router issue.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 23, 5, tzinfo=UTC),
        vendor_name="TPLINK",
        product_name="AX50 Wireless Router",
    )


def _poc_evidence_input(cve_id: str, source_record_id: str) -> EvidenceInput:
    return EvidenceInput(
        cve_id=cve_id,
        signal_type=EvidenceSignal.POC,
        status=EvidenceStatus.PRESENT,
        source_name="trusted-poc-db",
        source_record_id=source_record_id,
        evidence_timestamp=datetime(2026, 4, 2, 23, 10, tzinfo=UTC),
        collected_at=datetime(2026, 4, 2, 23, 10, tzinfo=UTC),
        freshness_ttl_seconds=14 * 24 * 60 * 60,
        confidence=0.92,
        raw_payload={"origin": "fixture"},
    )


def _valid_ai_payload(cve_id: str) -> dict[str, object]:
    return {
        "cve_id": cve_id,
        "enterprise_relevance_assessment": "enterprise_relevant",
        "exploit_path_assessment": "internet_exploitable",
        "confidence": 0.91,
        "reasoning_summary": "Relevant for enterprise edge deployments with a direct exploit path.",
    }
