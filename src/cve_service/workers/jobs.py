from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import create_engine

from cve_service.core.config import get_settings
from cve_service.core.db import create_session_factory, session_scope
from cve_service.services.enrichment import refresh_stale_evidence


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


def _coerce_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)
