from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from redis import Redis
from rq import Queue, SimpleWorker
from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import CVE, Evidence, OperationalMetric
from cve_service.models.enums import CveState, EvidenceSignal, EvidenceSourceType, EvidenceStatus
from cve_service.services.enrichment import EvidenceInput, record_evidence, refresh_stale_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publish_queue import RQPublishJobProducer
from cve_service.services.publication import publish_initial_publication
from cve_service.services.publish_targets import InMemoryPublishTarget


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


def test_phase5_metrics_are_persisted_deterministically_for_update_flow(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-metrics-{uuid4().hex}", connection=redis_client)
    producer = RQPublishJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        publish_target_name="inline",
        publish_target_behavior={
            "external_id": "inline-phase5-metrics-5400",
            "response_payload": {"channel": "phase5-metrics"},
        },
    )
    evidence_input = _update_evidence_input(
        "CVE-2026-5400",
        signal_type=EvidenceSignal.ITW,
        status=EvidenceStatus.PRESENT,
        source_type=EvidenceSourceType.KEV,
        source_name="cisa-kev",
        source_record_id="kev-cve-2026-5400",
        collected_at=datetime(2026, 4, 3, 1, 30, tzinfo=UTC),
        is_authoritative=True,
        confidence=0.99,
    )

    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5400", initial_signal=EvidenceSignal.POC)
        record_evidence(session, evidence_input, publish_producer=producer)

    with session_scope(session_factory) as session:
        record_evidence(session, evidence_input, publish_producer=producer)

    job_ids = queue.get_job_ids()
    assert len(job_ids) == 1

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job = queue.fetch_job(job_ids[0])
    assert job is not None
    job.refresh()

    try:
        with session_scope(session_factory) as session:
            created_metric = _get_metric(
                session,
                "phase5.update_candidate.evaluations.total",
                {"result": "created", "trigger": "evidence_upsert"},
            )
            reused_metric = _get_metric(
                session,
                "phase5.update_candidate.evaluations.total",
                {"result": "reused", "trigger": "evidence_upsert"},
            )
            enqueue_requested_metric = _get_metric(
                session,
                "phase5.update_enqueue.attempts.total",
                {
                    "publication_event_type": "UPDATE",
                    "result": "requested",
                    "target_name": "inline",
                    "trigger": "update_candidate_detected",
                },
            )
            enqueue_reused_metric = _get_metric(
                session,
                "phase5.update_enqueue.attempts.total",
                {
                    "publication_event_type": "UPDATE",
                    "result": "reused",
                    "target_name": "inline",
                    "trigger": "update_candidate_detected",
                },
            )
            publication_metric = _get_metric(
                session,
                "phase5.update_publication.outcomes.total",
                {
                    "event_type": "UPDATE",
                    "result": "succeeded",
                    "target_name": "inline",
                },
            )

        assert created_metric is not None
        assert created_metric.total_count == 1
        assert created_metric.last_details["cve_id"] == "CVE-2026-5400"
        assert created_metric.last_details["publication_job_id"] is not None

        assert reused_metric is not None
        assert reused_metric.total_count == 1
        assert reused_metric.last_details["publication_job_id"] == created_metric.last_details["publication_job_id"]

        assert enqueue_requested_metric is not None
        assert enqueue_requested_metric.total_count == 1
        assert enqueue_requested_metric.last_details["job_id"] == created_metric.last_details["publication_job_id"]

        assert enqueue_reused_metric is not None
        assert enqueue_reused_metric.total_count == 1
        assert enqueue_reused_metric.last_details["job_id"] == created_metric.last_details["publication_job_id"]

        assert publication_metric is not None
        assert publication_metric.total_count == 1
        assert publication_metric.last_details["cve_id"] == "CVE-2026-5400"
        assert publication_metric.last_details["triggering_update_candidate_id"] == created_metric.last_details["update_candidate_id"]
    finally:
        job.delete()
        redis_client.close()


def test_phase5_stale_refresh_metric_is_persisted_deterministically(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5401", initial_signal=EvidenceSignal.POC)
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5401"))
        evidence = session.scalar(
            select(Evidence)
            .where(Evidence.cve_id == cve.id, Evidence.signal_type == EvidenceSignal.POC)
            .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        )
        evidence.collected_at = datetime(2026, 4, 2, 0, 0, tzinfo=UTC)
        evidence.freshness_ttl_seconds = 60

        result = refresh_stale_evidence(
            session,
            evaluated_at=datetime(2026, 4, 3, 2, 0, tzinfo=UTC),
        )
        refresh_metric = _get_metric(
            session,
            "phase5.stale_evidence.refresh.total",
            {
                "action": "reevaluate_summary",
                "signal_type": "POC",
                "trigger": "stale_refresh",
            },
        )

    assert result.stale_targets == 1
    assert result.recomputed_cves == 1
    assert refresh_metric is not None
    assert refresh_metric.total_count == 1
    assert refresh_metric.last_details["cve_id"] == "CVE-2026-5401"
    assert refresh_metric.last_details["stale_records"] == 1


def _get_metric(session, metric_key: str, dimensions: dict[str, str]) -> OperationalMetric | None:
    normalized_dimensions = {key: dimensions[key] for key in sorted(dimensions)}
    dimension_key = hashlib.sha256(
        json.dumps(normalized_dimensions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return session.scalar(
        select(OperationalMetric)
        .where(
            OperationalMetric.metric_key == metric_key,
            OperationalMetric.dimension_key == dimension_key,
        )
        .limit(1)
    )


def _prepare_published_cve(session, cve_id: str, *, initial_signal: EvidenceSignal) -> None:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 5 observability fixture.",
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
