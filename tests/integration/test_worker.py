from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, Evidence
from cve_service.models.enums import AuditActorType, EvidenceSignal, EvidenceSourceType, EvidenceStatus
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from redis import Redis
from rq import Queue, SimpleWorker

from cve_service.workers.jobs import noop_job, refresh_stale_evidence_job


def test_worker_processes_noop_job(redis_url: str) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase0-noop-{uuid4().hex}", connection=redis_client)
    job = queue.enqueue(noop_job, {"probe": "phase0"})

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()

    try:
        assert job.is_finished is True
        assert job.return_value() == {"status": "processed", "payload": {"probe": "phase0"}}
    finally:
        job.delete()
        redis_client.close()


def test_worker_refresh_job_recomputes_stale_evidence(session_factory, migrated_engine, redis_url: str) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0300"))
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0300",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_record_id="stale-poc-2026-0300",
                evidence_timestamp=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                freshness_ttl_seconds=60 * 60,
                confidence=0.94,
                confidence_inputs={"base_confidence": 0.94},
            ),
        )

    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase2-refresh-{uuid4().hex}", connection=redis_client)
    job = queue.enqueue(
        refresh_stale_evidence_job,
        migrated_engine.url.render_as_string(hide_password=False),
        evaluated_at="2026-04-02T12:30:00+00:00",
    )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()

    try:
        assert job.is_finished is True
        assert job.return_value() == {
            "status": "processed",
            "evaluated_at": "2026-04-02T12:30:00+00:00",
            "stale_targets": 1,
            "recomputed_cves": 1,
            "cve_ids": ["CVE-2026-0300"],
        }

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0300"))
            evidence_items = session.scalars(select(Evidence)).all()
            refresh_events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.cve_id == cve.id,
                    AuditEvent.event_type == "enrichment.refresh_evaluated",
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.poc_status is EvidenceStatus.UNKNOWN
        assert cve.poc_confidence is None
        assert len(evidence_items) == 1
        assert len(refresh_events) == 1
        assert refresh_events[0].actor_type is AuditActorType.WORKER
        assert refresh_events[0].details["signal_type"] == "POC"
        assert refresh_events[0].details["stale_records"] == 1
    finally:
        job.delete()
        redis_client.close()


def _record(cve_id: str) -> PublicFeedRecord:
    return PublicFeedRecord(
        cve_id=cve_id,
        title="Exchange Server RCE",
        description="Phase 2 worker refresh slice.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 13, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )
