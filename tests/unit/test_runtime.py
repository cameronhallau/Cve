from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

from cve_service.runtime import (
    EXIT_INVALID_CONFIG,
    EXIT_SUCCESS,
    _handle_alert_eval_once,
    _handle_ingest_poll_once,
    _handle_stale_refresh_once,
    main,
)
from cve_service.services.alerting import OperationalAlertEvaluationResult
from cve_service.services.enrichment import RefreshRunResult
from cve_service.services.live_ingestion import LiveIngestionPollResult


class FakeEngine:
    def __init__(self) -> None:
        self.disposed = False

    def dispose(self) -> None:
        self.disposed = True


class FakeRedis:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_handle_ingest_poll_once_calls_live_poll_service(monkeypatch) -> None:
    captured: dict[str, object] = {}
    engine = FakeEngine()
    redis_client = FakeRedis()
    session = object()

    monkeypatch.setattr("cve_service.runtime.create_db_engine", lambda settings: engine)
    monkeypatch.setattr("cve_service.runtime.create_session_factory", lambda engine: "session-factory")
    monkeypatch.setattr("cve_service.runtime.create_redis_client", lambda settings: redis_client)
    monkeypatch.setattr("cve_service.runtime.create_queue", lambda settings, redis_client=None: "queue")
    monkeypatch.setattr("cve_service.runtime.ping_queue", lambda redis_client, queue: (True, "connected"))
    monkeypatch.setattr(
        "cve_service.runtime.RQPostEnrichmentJobProducer",
        lambda queue, database_url=None, ai_model_name=None, publish_target_name=None: {
            "queue": queue,
            "database_url": database_url,
            "ai_model_name": ai_model_name,
            "publish_target_name": publish_target_name,
        },
    )

    @contextmanager
    def fake_session_scope(_):
        yield session

    monkeypatch.setattr("cve_service.runtime.session_scope", fake_session_scope)

    def fake_poll(session_arg, source_client, **kwargs):
        captured["session"] = session_arg
        captured["source_client"] = source_client
        captured["kwargs"] = kwargs
        return LiveIngestionPollResult(
            source_name="cve.org",
            status="succeeded",
            started_at=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
            completed_at=datetime(2026, 4, 2, 14, 1, tzinfo=UTC),
            checkpoint_before=None,
            checkpoint_after="2026-04-02T14:00:00+00:00",
            delta_entries_seen=1,
            delta_entries_applied=1,
            unique_changes_seen=1,
            records_fetched=1,
            ingested_records=1,
            snapshots_created=1,
            classifications_created=1,
            post_enrichment_jobs=("post-enrichment:cve-2026-1200",),
            upstream_error_count=0,
        )

    monkeypatch.setattr("cve_service.runtime.poll_live_cve_org_feed", fake_poll)

    settings = SimpleNamespace(
        cve_org_delta_log_url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json",
        cve_org_http_timeout_seconds=20.0,
        database_url="postgresql://example.test/cve",
        ai_model="deepseek/deepseek-v3.2",
        publish_target_name="x",
    )

    exit_code = _handle_ingest_poll_once(settings, argparse.Namespace(polled_at="2026-04-02T14:00:00+00:00"))

    assert exit_code == EXIT_SUCCESS
    assert captured["session"] is session
    assert captured["kwargs"]["polled_at"] == datetime(2026, 4, 2, 14, 0, tzinfo=UTC)
    assert captured["kwargs"]["post_enrichment_producer"]["queue"] == "queue"
    assert captured["kwargs"]["post_enrichment_producer"]["database_url"] == "postgresql://example.test/cve"
    assert captured["kwargs"]["post_enrichment_producer"]["publish_target_name"] == "x"
    assert engine.disposed is True
    assert redis_client.closed is True


def test_handle_stale_refresh_once_calls_refresh_service(monkeypatch) -> None:
    captured: dict[str, object] = {}
    engine = FakeEngine()
    redis_client = FakeRedis()
    session = object()

    monkeypatch.setattr("cve_service.runtime.create_db_engine", lambda settings: engine)
    monkeypatch.setattr("cve_service.runtime.create_session_factory", lambda engine: "session-factory")
    monkeypatch.setattr("cve_service.runtime.create_redis_client", lambda settings: redis_client)
    monkeypatch.setattr("cve_service.runtime.create_queue", lambda settings, redis_client=None: "queue")
    monkeypatch.setattr("cve_service.runtime.ping_queue", lambda redis_client, queue: (True, "connected"))
    monkeypatch.setattr(
        "cve_service.runtime.RQPublishJobProducer",
        lambda queue, database_url=None, publish_target_name=None: {
            "queue": queue,
            "database_url": database_url,
            "publish_target_name": publish_target_name,
        },
    )

    @contextmanager
    def fake_session_scope(_):
        yield session

    monkeypatch.setattr("cve_service.runtime.session_scope", fake_session_scope)

    def fake_refresh(session_arg, **kwargs):
        captured["session"] = session_arg
        captured["kwargs"] = kwargs
        return RefreshRunResult(
            evaluated_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
            stale_targets=2,
            recomputed_cves=1,
            cve_ids=("CVE-2026-1300",),
        )

    monkeypatch.setattr("cve_service.runtime.refresh_stale_evidence", fake_refresh)

    settings = SimpleNamespace(
        database_url="postgresql://example.test/cve",
        publish_target_name="x",
    )

    exit_code = _handle_stale_refresh_once(
        settings,
        argparse.Namespace(evaluated_at="2026-04-02T15:00:00+00:00", limit=25),
    )

    assert exit_code == EXIT_SUCCESS
    assert captured["session"] is session
    assert captured["kwargs"]["limit"] == 25
    assert captured["kwargs"]["publish_producer"]["publish_target_name"] == "x"
    assert engine.disposed is True
    assert redis_client.closed is True


def test_handle_alert_eval_once_calls_alert_service(monkeypatch) -> None:
    captured: dict[str, object] = {}
    engine = FakeEngine()
    session = object()

    monkeypatch.setattr("cve_service.runtime.create_db_engine", lambda settings: engine)
    monkeypatch.setattr("cve_service.runtime.create_session_factory", lambda engine: "session-factory")

    @contextmanager
    def fake_session_scope(_):
        yield session

    monkeypatch.setattr("cve_service.runtime.session_scope", fake_session_scope)

    def fake_evaluate(session_arg, **kwargs):
        captured["session"] = session_arg
        captured["kwargs"] = kwargs
        return OperationalAlertEvaluationResult(
            evaluated_at=datetime(2026, 4, 2, 16, 0, tzinfo=UTC),
            active_alert_keys=("phase6.example",),
            activated_alert_keys=("phase6.example",),
            resolved_alert_keys=(),
        )

    monkeypatch.setattr("cve_service.runtime.evaluate_operational_alerts", fake_evaluate)

    exit_code = _handle_alert_eval_once(
        SimpleNamespace(),
        argparse.Namespace(evaluated_at="2026-04-02T16:00:00+00:00", trigger="runtime.test"),
    )

    assert exit_code == EXIT_SUCCESS
    assert captured["session"] is session
    assert captured["kwargs"]["trigger"] == "runtime.test"
    assert engine.disposed is True


def test_main_returns_invalid_config_exit_code_for_incomplete_x_settings(monkeypatch) -> None:
    monkeypatch.setenv("CVE_PUBLISH_TARGET_NAME", "x")
    monkeypatch.delenv("CVE_X_AUTH_MODE", raising=False)
    monkeypatch.delenv("CVE_X_CONSUMER_KEY", raising=False)
    monkeypatch.delenv("CVE_X_CONSUMER_SECRET", raising=False)
    monkeypatch.delenv("CVE_X_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("CVE_X_ACCESS_TOKEN_SECRET", raising=False)
    monkeypatch.delenv("CVE_X_BEARER_TOKEN", raising=False)

    exit_code = main(["alert-eval-once"])

    assert exit_code == EXIT_INVALID_CONFIG
