from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import create_engine

from cve_service.core.config import get_settings
from cve_service.core.db import create_session_factory, session_scope
from cve_service.services.ai_provider import build_ai_review_provider
from cve_service.services.enrichment import refresh_stale_evidence
from cve_service.services.post_enrichment import process_post_enrichment_workflow


def noop_job(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"status": "processed", "payload": payload or {}}


def refresh_stale_evidence_job(
    database_url: str | None = None,
    *,
    evaluated_at: str | datetime | None = None,
    limit: int | None = None,
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
            result = refresh_stale_evidence(
                session,
                evaluated_at=_coerce_datetime(evaluated_at),
                limit=limit,
            )
        return {
            "status": "processed",
            "evaluated_at": result.evaluated_at.isoformat(),
            "stale_targets": result.stale_targets,
            "recomputed_cves": result.recomputed_cves,
            "cve_ids": list(result.cve_ids),
        }
    finally:
        engine.dispose()


def process_post_enrichment_workflow_job(
    cve_id: str,
    database_url: str | None = None,
    *,
    ai_payload: dict[str, Any] | str | None = None,
    ai_model_name: str = "inline-worker-provider",
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

    try:
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
            )
        return {
            "status": "processed",
            "cve_id": result.cve_id,
            "state": result.state.value,
            "ai_review_id": str(result.ai_review_id) if result.ai_review_id is not None else None,
            "policy_decision_id": str(result.policy_decision_id) if result.policy_decision_id is not None else None,
            "ai_review_attempted": result.ai_review_attempted,
            "ai_review_skipped": result.ai_review_skipped,
            "ai_review_reused": result.ai_review_reused,
            "ai_retry_override_applied": result.ai_retry_override_applied,
            "policy_reused": result.policy_reused,
            "deferred": result.deferred,
            "deferred_reason_codes": list(result.deferred_reason_codes),
        }
    finally:
        engine.dispose()


def _coerce_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)
