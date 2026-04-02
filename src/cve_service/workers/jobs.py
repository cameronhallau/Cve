from __future__ import annotations

from datetime import datetime
from typing import Any

from redis import Redis
from rq import Queue, get_current_job
from sqlalchemy import create_engine

from cve_service.core.config import get_settings
from cve_service.core.db import create_session_factory, session_scope
from cve_service.services.ai_provider import build_ai_review_provider
from cve_service.services.enrichment import refresh_stale_evidence
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publish_queue import RQPublishJobProducer
from cve_service.services.publication import publish_publication
from cve_service.services.publish_targets import build_publish_target


def noop_job(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"status": "processed", "payload": payload or {}}


def refresh_stale_evidence_job(
    database_url: str | None = None,
    *,
    evaluated_at: str | datetime | None = None,
    limit: int | None = None,
    publish_target_name: str | None = None,
    publish_target_behavior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    engine = create_engine(
        database_url or settings.database_url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": int(settings.health_timeout_seconds)},
    )
    session_factory = create_session_factory(engine)
    redis_client: Redis | None = None

    try:
        publish_producer = None
        if publish_target_name is not None:
            redis_client = Redis.from_url(
                settings.redis_url,
                socket_connect_timeout=settings.health_timeout_seconds,
                socket_timeout=settings.health_timeout_seconds,
                decode_responses=False,
            )
            publish_producer = RQPublishJobProducer(
                Queue(name=_resolve_current_queue_name(settings.rq_queue_name), connection=redis_client),
                database_url=database_url or settings.database_url,
                publish_target_name=publish_target_name,
                publish_target_behavior=publish_target_behavior,
            )
        with session_scope(session_factory) as session:
            result = refresh_stale_evidence(
                session,
                evaluated_at=_coerce_datetime(evaluated_at),
                limit=limit,
                publish_producer=publish_producer,
            )
        return {
            "status": "processed",
            "evaluated_at": result.evaluated_at.isoformat(),
            "stale_targets": result.stale_targets,
            "recomputed_cves": result.recomputed_cves,
            "cve_ids": list(result.cve_ids),
        }
    finally:
        if redis_client is not None:
            redis_client.close()
        engine.dispose()


def process_post_enrichment_workflow_job(
    cve_id: str,
    database_url: str | None = None,
    *,
    ai_payload: dict[str, Any] | str | None = None,
    ai_model_name: str = "inline-worker-provider",
    publish_target_name: str | None = None,
    publish_target_behavior: dict[str, Any] | None = None,
    requested_at: str | datetime | None = None,
    evaluated_at: str | datetime | None = None,
    retry_ai_review: bool = False,
) -> dict[str, Any]:
    settings = get_settings()
    engine = create_engine(
        database_url or settings.database_url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": int(settings.health_timeout_seconds)},
    )
    session_factory = create_session_factory(engine)
    redis_client: Redis | None = None

    try:
        publish_producer = None
        if publish_target_name is not None:
            redis_client = Redis.from_url(
                settings.redis_url,
                socket_connect_timeout=settings.health_timeout_seconds,
                socket_timeout=settings.health_timeout_seconds,
                decode_responses=False,
            )
            publish_producer = RQPublishJobProducer(
                Queue(name=_resolve_current_queue_name(settings.rq_queue_name), connection=redis_client),
                database_url=database_url or settings.database_url,
                publish_target_name=publish_target_name,
                publish_target_behavior=publish_target_behavior,
            )
        with session_scope(session_factory) as session:
            provider = build_ai_review_provider(
                settings,
                ai_payload=ai_payload,
                ai_model_name=ai_model_name if ai_payload is not None else None,
            )
            result = process_post_enrichment_workflow(
                session,
                cve_id,
                provider,
                requested_at=_coerce_datetime(requested_at),
                evaluated_at=_coerce_datetime(evaluated_at),
                retry_ai_review=retry_ai_review,
                publish_producer=publish_producer,
            )
        return {
            "status": "processed",
            "cve_id": result.cve_id,
            "state": result.state.value,
            "ai_review_id": str(result.ai_review_id) if result.ai_review_id is not None else None,
            "policy_decision_id": str(result.policy_decision_id) if result.policy_decision_id is not None else None,
            "publication_job_id": result.publication_job_id,
            "ai_review_attempted": result.ai_review_attempted,
            "ai_review_skipped": result.ai_review_skipped,
            "ai_review_reused": result.ai_review_reused,
            "ai_retry_override_applied": result.ai_retry_override_applied,
            "policy_reused": result.policy_reused,
            "deferred": result.deferred,
            "deferred_reason_codes": list(result.deferred_reason_codes),
        }
    finally:
        if redis_client is not None:
            redis_client.close()
        engine.dispose()


def process_publication_job(
    cve_id: str,
    database_url: str | None = None,
    *,
    publish_target_name: str = "console",
    publish_target_behavior: dict[str, Any] | None = None,
    attempted_at: str | datetime | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    engine = create_engine(
        database_url or settings.database_url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": int(settings.health_timeout_seconds)},
    )
    session_factory = create_session_factory(engine)

    try:
        with session_scope(session_factory) as session:
            target = build_publish_target(
                target_name=publish_target_name,
                behavior=publish_target_behavior,
            )
            result = publish_publication(
                session,
                cve_id,
                target,
                attempted_at=_coerce_datetime(attempted_at),
            )
        return {
            "status": "processed" if result.published or result.duplicate_blocked else "failed",
            "cve_id": result.cve_id,
            "state": result.state.value,
            "decision_id": str(result.decision_id) if result.decision_id is not None else None,
            "publication_event_id": str(result.event_id),
            "publication_event_type": result.event_type.value,
            "publication_status": result.event_status.value,
            "target_name": result.target_name,
            "content_hash": result.content_hash,
            "idempotency_key": result.idempotency_key,
            "published": result.published,
            "duplicate_blocked": result.duplicate_blocked,
            "reused_event": result.reused_event,
            "attempt_count": result.attempt_count,
            "external_id": result.external_id,
        }
    finally:
        engine.dispose()


def _coerce_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def _resolve_current_queue_name(default_queue_name: str) -> str:
    current_job = get_current_job()
    if current_job is None:
        return default_queue_name
    return current_job.origin
