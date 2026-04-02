from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Sequence

from pydantic import ValidationError

from cve_service.core.config import Settings
from cve_service.core.db import create_db_engine, create_session_factory, session_scope
from cve_service.core.queue import create_queue, create_redis_client, ping_queue
from cve_service.services.alerting import evaluate_operational_alerts
from cve_service.services.enrichment import refresh_stale_evidence
from cve_service.services.live_ingestion import CveOrgDeltaLogClient, poll_live_cve_org_feed
from cve_service.services.post_enrichment_queue import RQPostEnrichmentJobProducer
from cve_service.services.publish_queue import RQPublishJobProducer

EXIT_SUCCESS = 0
EXIT_RUNTIME_FAILURE = 1
EXIT_INVALID_CONFIG = 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        settings = Settings()
        return args.handler(settings, args)
    except ValidationError as exc:
        _emit(
            {
                "status": "invalid_config",
                "error": str(exc),
            },
            stream=sys.stderr,
        )
        return EXIT_INVALID_CONFIG
    except Exception as exc:
        _emit(
            {
                "status": "failed",
                "error": str(exc),
                "exception_type": exc.__class__.__name__,
            },
            stream=sys.stderr,
        )
        return EXIT_RUNTIME_FAILURE


def run_ingest_poll_once() -> None:
    raise SystemExit(main(["ingest-poll-once"]))


def run_stale_refresh_once() -> None:
    raise SystemExit(main(["stale-refresh-once"]))


def run_alert_evaluation_once() -> None:
    raise SystemExit(main(["alert-eval-once"]))


def run_runtime() -> None:
    raise SystemExit(main())


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest-poll-once", help="Poll the live CVE.org public feed once.")
    ingest_parser.add_argument("--polled-at", dest="polled_at")
    ingest_parser.set_defaults(handler=_handle_ingest_poll_once)

    refresh_parser = subparsers.add_parser("stale-refresh-once", help="Refresh stale evidence once.")
    refresh_parser.add_argument("--evaluated-at", dest="evaluated_at")
    refresh_parser.add_argument("--limit", dest="limit", type=int)
    refresh_parser.set_defaults(handler=_handle_stale_refresh_once)

    alert_parser = subparsers.add_parser("alert-eval-once", help="Evaluate operational alerts once.")
    alert_parser.add_argument("--evaluated-at", dest="evaluated_at")
    alert_parser.add_argument("--trigger", dest="trigger", default="runtime.alert_eval_once")
    alert_parser.set_defaults(handler=_handle_alert_eval_once)

    return parser


def _handle_ingest_poll_once(settings: Settings, args: argparse.Namespace) -> int:
    redis_client, queue = _preflight_queue(settings)
    engine = create_db_engine(settings)
    session_factory = create_session_factory(engine)

    try:
        with session_scope(session_factory) as session:
            result = poll_live_cve_org_feed(
                session,
                CveOrgDeltaLogClient(
                    delta_log_url=settings.cve_org_delta_log_url,
                    timeout_seconds=settings.cve_org_http_timeout_seconds,
                ),
                polled_at=_parse_optional_datetime(args.polled_at),
                post_enrichment_producer=RQPostEnrichmentJobProducer(
                    queue,
                    database_url=settings.database_url,
                    ai_model_name=settings.ai_model,
                ),
            )
        stream = sys.stderr if result.status == "failed" else sys.stdout
        _emit(_poll_result_payload(result), stream=stream)
        return EXIT_SUCCESS if result.status != "failed" else EXIT_RUNTIME_FAILURE
    finally:
        redis_client.close()
        engine.dispose()


def _handle_stale_refresh_once(settings: Settings, args: argparse.Namespace) -> int:
    redis_client, queue = _preflight_queue(settings)
    engine = create_db_engine(settings)
    session_factory = create_session_factory(engine)

    try:
        with session_scope(session_factory) as session:
            result = refresh_stale_evidence(
                session,
                evaluated_at=_parse_optional_datetime(args.evaluated_at),
                limit=args.limit,
                publish_producer=RQPublishJobProducer(
                    queue,
                    database_url=settings.database_url,
                    publish_target_name=settings.publish_target_name,
                ),
            )
        _emit(
            {
                "status": "processed",
                "evaluated_at": result.evaluated_at.isoformat(),
                "stale_targets": result.stale_targets,
                "recomputed_cves": result.recomputed_cves,
                "cve_ids": list(result.cve_ids),
                "publish_target_name": settings.publish_target_name,
            }
        )
        return EXIT_SUCCESS
    finally:
        redis_client.close()
        engine.dispose()


def _handle_alert_eval_once(settings: Settings, args: argparse.Namespace) -> int:
    engine = create_db_engine(settings)
    session_factory = create_session_factory(engine)

    try:
        with session_scope(session_factory) as session:
            result = evaluate_operational_alerts(
                session,
                evaluated_at=_parse_optional_datetime(args.evaluated_at),
                trigger=args.trigger,
            )
        _emit(
            {
                "status": "processed",
                "evaluated_at": result.evaluated_at.isoformat(),
                "active_alert_keys": list(result.active_alert_keys),
                "activated_alert_keys": list(result.activated_alert_keys),
                "resolved_alert_keys": list(result.resolved_alert_keys),
            }
        )
        return EXIT_SUCCESS
    finally:
        engine.dispose()


def _preflight_queue(settings: Settings):
    redis_client = create_redis_client(settings)
    queue = create_queue(settings, redis_client)
    queue_ok, queue_detail = ping_queue(redis_client, queue)
    if not queue_ok:
        redis_client.close()
        raise RuntimeError(f"queue preflight failed: {queue_detail}")
    return redis_client, queue


def _parse_optional_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _emit(payload: dict[str, Any], *, stream=sys.stdout) -> None:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
    stream.flush()


def _poll_result_payload(result) -> dict[str, Any]:
    return {
        "status": result.status,
        "source_name": result.source_name,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat(),
        "checkpoint_before": result.checkpoint_before,
        "checkpoint_after": result.checkpoint_after,
        "delta_entries_seen": result.delta_entries_seen,
        "delta_entries_applied": result.delta_entries_applied,
        "unique_changes_seen": result.unique_changes_seen,
        "records_fetched": result.records_fetched,
        "ingested_records": result.ingested_records,
        "snapshots_created": result.snapshots_created,
        "classifications_created": result.classifications_created,
        "post_enrichment_jobs": list(result.post_enrichment_jobs),
        "upstream_error_count": result.upstream_error_count,
        "error_stage": result.error_stage,
        "error_message": result.error_message,
        "error_details": result.error_details or {},
    }


if __name__ == "__main__":
    raise SystemExit(main())
