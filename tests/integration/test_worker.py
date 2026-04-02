from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AIReview, AuditEvent, CVE, Evidence, PolicyDecision, PublicationEvent, UpdateCandidate
from cve_service.models.enums import (
    AuditActorType,
    CveState,
    EvidenceSignal,
    EvidenceSourceType,
    EvidenceStatus,
    PolicyDecisionOutcome,
    PublicationEventType,
)
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.post_enrichment_queue import RQPostEnrichmentJobProducer
from cve_service.services.publication import publish_initial_publication
from cve_service.services.publish_targets import InMemoryPublishTarget
from redis import Redis
from rq import Queue, SimpleWorker

from cve_service.workers.jobs import noop_job, process_post_enrichment_workflow_job, refresh_stale_evidence_job


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


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


def test_worker_refresh_job_enqueues_and_publishes_material_update_from_stale_refresh(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-0301")
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0301"))
        evidence = session.scalar(
            select(Evidence)
            .where(Evidence.cve_id == cve.id, Evidence.signal_type == EvidenceSignal.POC)
            .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        )
        evidence.collected_at = datetime(2026, 4, 2, 0, 0, tzinfo=UTC)
        evidence.freshness_ttl_seconds = 60

    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase5-refresh-update-{uuid4().hex}", connection=redis_client)
    job = queue.enqueue(
        refresh_stale_evidence_job,
        migrated_engine.url.render_as_string(hide_password=False),
        evaluated_at="2026-04-03T02:00:00+00:00",
        publish_target_name="inline",
        publish_target_behavior={
            "external_id": "inline-refresh-0301",
            "response_payload": {"channel": "phase5-refresh"},
        },
    )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()

    try:
        assert job.is_finished is True
        assert job.return_value() == {
            "status": "processed",
            "evaluated_at": "2026-04-03T02:00:00+00:00",
            "stale_targets": 1,
            "recomputed_cves": 1,
            "cve_ids": ["CVE-2026-0301"],
        }

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0301"))
            candidate = session.scalar(select(UpdateCandidate).where(UpdateCandidate.cve_id == cve.id))
            update_events = session.scalars(
                select(PublicationEvent)
                .where(
                    PublicationEvent.cve_id == cve.id,
                    PublicationEvent.event_type == PublicationEventType.UPDATE,
                )
                .order_by(PublicationEvent.created_at.asc(), PublicationEvent.id.asc())
            ).all()
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.cve_id == cve.id,
                    AuditEvent.event_type == "workflow.publish_enqueue_requested",
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert candidate is not None
        assert cve.state is CveState.PUBLISHED
        assert len(update_events) == 1
        assert update_events[0].triggering_update_candidate_id == candidate.id
        assert len(enqueue_events) == 1
        assert enqueue_events[0].details["trigger"] == "update_candidate_detected"
    finally:
        job.delete()
        redis_client.close()


def test_worker_refresh_job_rerun_keeps_update_handoff_idempotent(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-0302")
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0302"))
        evidence = session.scalar(
            select(Evidence)
            .where(Evidence.cve_id == cve.id, Evidence.signal_type == EvidenceSignal.POC)
            .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        )
        evidence.collected_at = datetime(2026, 4, 2, 0, 0, tzinfo=UTC)
        evidence.freshness_ttl_seconds = 60

    first_job, first_redis = _run_refresh_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        evaluated_at="2026-04-03T02:00:00+00:00",
        cve_fixture="phase5-refresh-rerun",
    )

    second_job, second_redis = _run_refresh_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        evaluated_at="2026-04-03T02:00:00+00:00",
        cve_fixture="phase5-refresh-rerun",
    )

    try:
        assert first_job.return_value()["status"] == "processed"
        assert second_job.return_value()["status"] == "processed"

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0302"))
            candidates = session.scalars(
                select(UpdateCandidate)
                .where(UpdateCandidate.cve_id == cve.id)
                .order_by(UpdateCandidate.created_at.asc(), UpdateCandidate.id.asc())
            ).all()
            update_events = session.scalars(
                select(PublicationEvent)
                .where(
                    PublicationEvent.cve_id == cve.id,
                    PublicationEvent.event_type == PublicationEventType.UPDATE,
                )
                .order_by(PublicationEvent.created_at.asc(), PublicationEvent.id.asc())
            ).all()
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.cve_id == cve.id,
                    AuditEvent.event_type.in_(
                        (
                            "workflow.publish_enqueue_requested",
                            "workflow.publish_enqueue_reused",
                        )
                    ),
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISHED
        assert len(candidates) == 1
        assert len(update_events) == 1
        assert [event.event_type for event in enqueue_events] == ["workflow.publish_enqueue_requested"]
    finally:
        first_job.delete()
        second_job.delete()
        first_redis.close()
        second_redis.close()


def test_record_evidence_enqueues_post_enrichment_job_after_commit(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase3-enqueue-{uuid4().hex}", connection=redis_client)

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0605"))
        record_evidence(
            session,
            _poc_evidence_input("CVE-2026-0605", "poc-2026-0605"),
            post_enrichment_producer=RQPostEnrichmentJobProducer(
                queue,
                database_url=migrated_engine.url.render_as_string(hide_password=False),
                ai_payload=_valid_ai_payload("CVE-2026-0605"),
            ),
        )
        assert queue.get_job_ids() == []

    job_ids = queue.get_job_ids()
    assert len(job_ids) == 1
    job = queue.fetch_job(job_ids[0])
    assert job is not None

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()

    try:
        assert job.return_value()["status"] == "processed"
        assert job.return_value()["state"] == "PUBLISH_PENDING"

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0605"))
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_type == "workflow.post_enrichment_enqueue_requested")
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISH_PENDING
        assert len(enqueue_events) == 1
        assert enqueue_events[0].details["trigger"] == "evidence_upsert"
        assert enqueue_events[0].details["retry_ai_review"] is False
    finally:
        job.delete()
        redis_client.close()


def test_record_evidence_enqueue_is_idempotent_for_same_summary_before_worker_runs(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase3-enqueue-reuse-{uuid4().hex}", connection=redis_client)
    producer = RQPostEnrichmentJobProducer(
        queue,
        database_url=migrated_engine.url.render_as_string(hide_password=False),
        ai_payload=_valid_ai_payload("CVE-2026-0606"),
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0606"))
        record_evidence(
            session,
            _poc_evidence_input("CVE-2026-0606", "poc-2026-0606"),
            post_enrichment_producer=producer,
        )

    with session_scope(session_factory) as session:
        record_evidence(
            session,
            _poc_evidence_input("CVE-2026-0606", "poc-2026-0606"),
            post_enrichment_producer=producer,
        )

    job_ids = queue.get_job_ids()
    assert len(job_ids) == 1
    job = queue.fetch_job(job_ids[0])
    assert job is not None

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()

    try:
        assert job.return_value()["status"] == "processed"
        assert job.return_value()["state"] == "PUBLISH_PENDING"

        with session_scope(session_factory) as session:
            enqueue_events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.event_type.in_(
                        (
                            "workflow.post_enrichment_enqueue_requested",
                            "workflow.post_enrichment_enqueue_reused",
                        )
                    )
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert [event.event_type for event in enqueue_events] == [
            "workflow.post_enrichment_enqueue_requested",
            "workflow.post_enrichment_enqueue_reused",
        ]
        assert enqueue_events[0].details["job_id"] == enqueue_events[1].details["job_id"]
    finally:
        job.delete()
        redis_client.close()


def test_worker_post_enrichment_job_routes_ambiguous_case_through_ai_then_policy(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0600"))
        record_evidence(session, _poc_evidence_input("CVE-2026-0600", "poc-2026-0600"))

    job, redis_client = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0600",
        ai_payload=_valid_ai_payload("CVE-2026-0600"),
        requested_at="2026-04-02T20:00:00+00:00",
        evaluated_at="2026-04-02T20:05:00+00:00",
    )

    try:
        assert job.return_value()["status"] == "processed"
        assert job.return_value()["state"] == "PUBLISH_PENDING"
        assert job.return_value()["ai_review_attempted"] is True
        assert job.return_value()["ai_review_reused"] is False
        assert job.return_value()["policy_reused"] is False

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0600"))
            reviews = session.scalars(select(AIReview)).all()
            decisions = session.scalars(select(PolicyDecision)).all()
            audit_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.cve_id == cve.id)
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISH_PENDING
        assert len(reviews) == 1
        assert len(decisions) == 1
        assert decisions[0].decision is PolicyDecisionOutcome.PUBLISH
        relevant_event_types = {
            event.event_type
            for event in audit_events
            if event.event_type.startswith("workflow.") or event.event_type.startswith("ai_review") or event.event_type.startswith("policy.")
        }
        assert relevant_event_types == {
            "workflow.post_enrichment_started",
            "ai_review.persisted",
            "policy.decision_made",
            "workflow.post_enrichment_completed",
        }
    finally:
        job.delete()
        redis_client.close()


def test_worker_post_enrichment_job_skips_ai_for_non_ambiguous_candidate(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0601"))
        record_evidence(session, _poc_evidence_input("CVE-2026-0601", "poc-2026-0601"))

    job, redis_client = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0601",
        ai_payload=_valid_ai_payload("CVE-2026-0601"),
        requested_at="2026-04-02T20:10:00+00:00",
        evaluated_at="2026-04-02T20:15:00+00:00",
    )

    try:
        assert job.return_value()["state"] == "PUBLISH_PENDING"
        assert job.return_value()["ai_review_attempted"] is False
        assert job.return_value()["ai_review_skipped"] is True

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0601"))
            reviews = session.scalars(select(AIReview)).all()
            decisions = session.scalars(select(PolicyDecision)).all()
            skip_events = session.scalars(select(AuditEvent).where(AuditEvent.event_type == "ai_review.skipped")).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISH_PENDING
        assert reviews == []
        assert len(decisions) == 1
        assert len(skip_events) == 1
    finally:
        job.delete()
        redis_client.close()


def test_worker_post_enrichment_job_invalid_ai_defers_without_policy_advance(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0602"))

    job, redis_client = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0602",
        ai_payload="{not-json",
        requested_at="2026-04-02T20:20:00+00:00",
        evaluated_at="2026-04-02T20:25:00+00:00",
    )

    try:
        assert job.return_value()["state"] == "DEFERRED"
        assert job.return_value()["policy_decision_id"] is None
        assert job.return_value()["deferred"] is True
        assert job.return_value()["deferred_reason_codes"] == ["policy.defer.ai_invalid_review"]

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0602"))
            reviews = session.scalars(select(AIReview)).all()
            decisions = session.scalars(select(PolicyDecision)).all()
            deferred_events = session.scalars(
                select(AuditEvent).where(AuditEvent.event_type == "workflow.deferred_recorded")
            ).all()

        assert cve is not None
        assert cve.state is CveState.DEFERRED
        assert len(reviews) == 1
        assert decisions == []
        assert len(deferred_events) == 1
        assert deferred_events[0].details["source"] == "ai_review"
    finally:
        job.delete()
        redis_client.close()


def test_worker_post_enrichment_job_is_idempotent_on_rerun(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0603"))
        record_evidence(session, _poc_evidence_input("CVE-2026-0603", "poc-2026-0603"))

    first_job, first_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0603",
        ai_payload=_valid_ai_payload("CVE-2026-0603"),
        requested_at="2026-04-02T20:30:00+00:00",
        evaluated_at="2026-04-02T20:35:00+00:00",
    )
    second_job, second_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0603",
        ai_payload=_valid_ai_payload("CVE-2026-0603"),
        requested_at="2026-04-02T20:30:00+00:00",
        evaluated_at="2026-04-02T20:35:00+00:00",
    )

    try:
        assert first_job.return_value()["ai_review_reused"] is False
        assert first_job.return_value()["policy_reused"] is False
        assert second_job.return_value()["ai_review_reused"] is True
        assert second_job.return_value()["policy_reused"] is True

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0603"))
            reviews = session.scalars(select(AIReview)).all()
            decisions = session.scalars(select(PolicyDecision)).all()
            reused_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_type.in_(("ai_review.reused", "policy.decision_reused")))
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISH_PENDING
        assert len(reviews) == 1
        assert len(decisions) == 1
        assert {event.event_type for event in reused_events} == {"ai_review.reused", "policy.decision_reused"}
    finally:
        first_job.delete()
        second_job.delete()
        first_redis.close()
        second_redis.close()


def test_worker_post_enrichment_job_records_deferred_and_retries_safely(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0604"))

    first_job, first_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0604",
        ai_payload=_valid_ai_payload("CVE-2026-0604"),
        requested_at="2026-04-02T20:40:00+00:00",
        evaluated_at="2026-04-02T20:45:00+00:00",
    )

    with session_scope(session_factory) as session:
        record_evidence(session, _poc_evidence_input("CVE-2026-0604", "poc-2026-0604"))

    second_job, second_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0604",
        ai_payload=_valid_ai_payload("CVE-2026-0604"),
        requested_at="2026-04-02T20:40:00+00:00",
        evaluated_at="2026-04-02T20:50:00+00:00",
    )

    try:
        assert first_job.return_value()["state"] == "DEFERRED"
        assert first_job.return_value()["deferred_reason_codes"] == ["policy.defer.awaiting_exploit_evidence"]
        assert second_job.return_value()["state"] == "PUBLISH_PENDING"

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0604"))
            decisions = session.scalars(
                select(PolicyDecision).order_by(PolicyDecision.created_at.asc(), PolicyDecision.id.asc())
            ).all()
            deferred_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_type == "workflow.deferred_recorded")
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISH_PENDING
        assert [decision.decision for decision in decisions] == [
            PolicyDecisionOutcome.DEFER,
            PolicyDecisionOutcome.PUBLISH,
        ]
        assert deferred_events[0].details["source"] == "policy_gate"
        assert deferred_events[0].details["reason_codes"] == ["policy.defer.awaiting_exploit_evidence"]
    finally:
        first_job.delete()
        second_job.delete()
        first_redis.close()
        second_redis.close()


def test_worker_post_enrichment_job_retry_override_retries_invalid_ai_review_explicitly(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0607"))
        record_evidence(session, _poc_evidence_input("CVE-2026-0607", "poc-2026-0607"))

    first_job, first_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0607",
        ai_payload="{not-json",
        requested_at="2026-04-02T21:00:00+00:00",
        evaluated_at="2026-04-02T21:05:00+00:00",
    )
    second_job, second_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0607",
        ai_payload=_valid_ai_payload("CVE-2026-0607"),
        requested_at="2026-04-02T21:10:00+00:00",
        evaluated_at="2026-04-02T21:15:00+00:00",
        retry_ai_review=True,
    )

    try:
        assert first_job.return_value()["state"] == "DEFERRED"
        assert second_job.return_value()["state"] == "PUBLISH_PENDING"
        assert second_job.return_value()["ai_retry_override_applied"] is True
        assert second_job.return_value()["ai_review_reused"] is False

        with session_scope(session_factory) as session:
            cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0607"))
            reviews = session.scalars(select(AIReview).order_by(AIReview.created_at.asc(), AIReview.id.asc())).all()
            decisions = session.scalars(select(PolicyDecision).order_by(PolicyDecision.created_at.asc(), PolicyDecision.id.asc())).all()
            retry_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_type == "ai_review.retry_override_requested")
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert cve is not None
        assert cve.state is CveState.PUBLISH_PENDING
        assert len(reviews) == 2
        assert [review.schema_valid for review in reviews] == [False, True]
        assert len(decisions) == 1
        assert len(retry_events) == 1
        assert retry_events[0].details["previous_outcome"] == "INVALID"
    finally:
        first_job.delete()
        second_job.delete()
        first_redis.close()
        second_redis.close()


def test_worker_post_enrichment_job_retry_override_retries_advisory_defer_explicitly(
    session_factory,
    migrated_engine,
    redis_url: str,
) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _ambiguous_record("CVE-2026-0608"))
        record_evidence(session, _poc_evidence_input("CVE-2026-0608", "poc-2026-0608"))

    first_job, first_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0608",
        ai_payload=_deferred_ai_payload("CVE-2026-0608"),
        requested_at="2026-04-02T21:20:00+00:00",
        evaluated_at="2026-04-02T21:25:00+00:00",
    )
    second_job, second_redis = _run_workflow_job(
        redis_url,
        migrated_engine.url.render_as_string(hide_password=False),
        "CVE-2026-0608",
        ai_payload=_valid_ai_payload("CVE-2026-0608"),
        requested_at="2026-04-02T21:30:00+00:00",
        evaluated_at="2026-04-02T21:35:00+00:00",
        retry_ai_review=True,
    )

    try:
        assert first_job.return_value()["state"] == "DEFERRED"
        assert second_job.return_value()["state"] == "PUBLISH_PENDING"
        assert second_job.return_value()["ai_retry_override_applied"] is True

        with session_scope(session_factory) as session:
            reviews = session.scalars(select(AIReview).order_by(AIReview.created_at.asc(), AIReview.id.asc())).all()
            decisions = session.scalars(select(PolicyDecision).order_by(PolicyDecision.created_at.asc(), PolicyDecision.id.asc())).all()
            retry_events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.event_type == "ai_review.retry_override_requested")
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).all()

        assert [review.outcome.value for review in reviews] == ["ADVISORY_DEFER", "ADVISORY_PUBLISH"]
        assert [decision.decision for decision in decisions] == [
            PolicyDecisionOutcome.DEFER,
            PolicyDecisionOutcome.PUBLISH,
        ]
        assert retry_events[0].details["previous_outcome"] == "ADVISORY_DEFER"
    finally:
        first_job.delete()
        second_job.delete()
        first_redis.close()
        second_redis.close()


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


def _prepare_published_cve(session, cve_id: str) -> None:
    ingest_public_feed_record(session, _record(cve_id))
    record_evidence(
        session,
        EvidenceInput(
            cve_id=cve_id,
            signal_type=EvidenceSignal.POC,
            status=EvidenceStatus.PRESENT,
            source_name="trusted-poc-db",
            source_type=EvidenceSourceType.TRUSTED_POC,
            source_record_id=f"initial-poc-{cve_id.lower()}",
            evidence_timestamp=datetime(2026, 4, 2, 19, 10, tzinfo=UTC),
            collected_at=datetime(2026, 4, 2, 19, 10, tzinfo=UTC),
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=0.94,
            raw_payload={"origin": "phase5-refresh"},
        ),
    )
    workflow_result = process_post_enrichment_workflow(
        session,
        cve_id,
        NeverCalledProvider(),
        requested_at=datetime(2026, 4, 2, 19, 11, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 2, 19, 11, tzinfo=UTC),
    )
    assert workflow_result.state is CveState.PUBLISH_PENDING
    publish_initial_publication(
        session,
        cve_id,
        InMemoryPublishTarget(name=f"phase5-refresh-initial-{cve_id.lower()}"),
        attempted_at=datetime(2026, 4, 2, 19, 12, tzinfo=UTC),
    )


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


def _poc_evidence_input(cve_id: str, source_record_id: str) -> EvidenceInput:
    return EvidenceInput(
        cve_id=cve_id,
        signal_type=EvidenceSignal.POC,
        status=EvidenceStatus.PRESENT,
        source_name="trusted-poc-db",
        source_record_id=source_record_id,
        evidence_timestamp=datetime(2026, 4, 2, 19, 10, tzinfo=UTC),
        collected_at=datetime(2026, 4, 2, 19, 10, tzinfo=UTC),
        freshness_ttl_seconds=14 * 24 * 60 * 60,
        confidence=0.9,
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


def _deferred_ai_payload(cve_id: str) -> dict[str, object]:
    return {
        "cve_id": cve_id,
        "enterprise_relevance_assessment": "unknown",
        "exploit_path_assessment": "unclear",
        "confidence": 0.89,
        "reasoning_summary": "The enterprise relevance is ambiguous with insufficient exploit path clarity.",
    }


def _run_workflow_job(
    redis_url: str,
    database_url: str,
    cve_id: str,
    *,
    ai_payload: dict[str, object] | str,
    requested_at: str,
    evaluated_at: str,
    retry_ai_review: bool = False,
)-> tuple:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase3-workflow-{uuid4().hex}", connection=redis_client)
    job = queue.enqueue(
        process_post_enrichment_workflow_job,
        cve_id,
        database_url,
        ai_payload=ai_payload,
        requested_at=requested_at,
        evaluated_at=evaluated_at,
        retry_ai_review=retry_ai_review,
    )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()
    return job, redis_client


def _run_refresh_job(
    redis_url: str,
    database_url: str,
    *,
    evaluated_at: str,
    cve_fixture: str,
) -> tuple:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"{cve_fixture}-{uuid4().hex}", connection=redis_client)
    job = queue.enqueue(
        refresh_stale_evidence_job,
        database_url,
        evaluated_at=evaluated_at,
        publish_target_name="inline",
        publish_target_behavior={
            "external_id": "inline-refresh-rerun",
            "response_payload": {"channel": "phase5-refresh"},
        },
    )

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()
    return job, redis_client
