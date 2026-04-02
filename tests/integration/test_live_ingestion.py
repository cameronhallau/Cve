from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, CVEIngestionSnapshot, Classification, OperationalMetric, SourceProgress
from cve_service.services.live_ingestion import (
    LIVE_INGEST_RUN_METRIC_KEY,
    DeltaChangePayload,
    DeltaEntry,
    poll_live_cve_org_feed,
)


class StaticLiveSourceClient:
    def __init__(self, entries: list[DeltaEntry], records: dict[str, dict[str, object]]) -> None:
        self.entries = entries
        self.records = records
        self.requested_urls: list[str] = []

    def fetch_delta_entries(self) -> list[DeltaEntry]:
        return list(self.entries)

    def fetch_record(self, record_url: str) -> dict[str, object]:
        self.requested_urls.append(record_url)
        return dict(self.records[record_url])


class RecordingPostEnrichmentProducer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def schedule(
        self,
        session,
        cve_id: str,
        *,
        trigger: str,
        requested_at=None,
        evaluated_at=None,
        retry_ai_review: bool = False,
        actor_type=None,
    ) -> str:
        self.calls.append((cve_id, trigger))
        return f"post-enrichment:{cve_id.lower()}"


def test_live_poll_ingests_records_advances_checkpoint_and_enqueues_post_enrichment(session_factory) -> None:
    record_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1100.json"
    source_client = StaticLiveSourceClient(
        [
            _delta_entry(
                "2026-04-02T10:00:00Z",
                [
                    {
                        "cveId": "CVE-2026-1100",
                        "githubLink": record_url,
                        "dateUpdated": "2026-04-02T09:55:00Z",
                    }
                ],
            )
        ],
        {
            record_url: _record_payload("CVE-2026-1100"),
        },
    )
    producer = RecordingPostEnrichmentProducer()

    with session_scope(session_factory) as session:
        result = poll_live_cve_org_feed(
            session,
            source_client,
            polled_at=datetime(2026, 4, 2, 10, 1, tzinfo=UTC),
            post_enrichment_producer=producer,
        )
        progress = session.scalar(select(SourceProgress).where(SourceProgress.source_name == "cve.org"))
        snapshots = session.scalars(select(CVEIngestionSnapshot)).all()
        classifications = session.scalars(select(Classification)).all()
        audit_events = session.scalars(
            select(AuditEvent).where(AuditEvent.entity_type == "source_progress").order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()
        metric = _get_metric(
            session,
            LIVE_INGEST_RUN_METRIC_KEY,
            {"failure_stage": "none", "result": "succeeded", "source_name": "cve.org"},
        )

    assert result.status == "succeeded"
    assert result.checkpoint_before is None
    assert result.checkpoint_after == "2026-04-02T10:00:00+00:00"
    assert result.ingested_records == 1
    assert result.snapshots_created == 1
    assert result.classifications_created == 1
    assert result.post_enrichment_jobs == ("post-enrichment:cve-2026-1100",)
    assert progress is not None
    assert progress.cursor == {"last_successful_fetch_time": "2026-04-02T10:00:00+00:00"}
    assert progress.last_run_status == "SUCCEEDED"
    assert progress.consecutive_failures == 0
    assert len(snapshots) == 1
    assert len(classifications) == 1
    assert sorted(event.event_type for event in audit_events) == ["ingestion.poll_started", "ingestion.poll_succeeded"]
    assert producer.calls == [("CVE-2026-1100", "ingestion.live_poll")]
    assert metric is not None
    assert metric.total_count == 1
    assert metric.last_details["checkpoint_after"] == "2026-04-02T10:00:00+00:00"


def test_live_poll_rerun_with_unchanged_checkpoint_is_noop_and_idempotent(session_factory) -> None:
    record_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1101.json"
    source_client = StaticLiveSourceClient(
        [
            _delta_entry(
                "2026-04-02T11:00:00Z",
                [
                    {
                        "cveId": "CVE-2026-1101",
                        "githubLink": record_url,
                        "dateUpdated": "2026-04-02T10:55:00Z",
                    }
                ],
            )
        ],
        {
            record_url: _record_payload("CVE-2026-1101"),
        },
    )

    with session_scope(session_factory) as session:
        first = poll_live_cve_org_feed(session, source_client, polled_at=datetime(2026, 4, 2, 11, 1, tzinfo=UTC))

    with session_scope(session_factory) as session:
        second = poll_live_cve_org_feed(session, source_client, polled_at=datetime(2026, 4, 2, 11, 5, tzinfo=UTC))
        snapshots = session.scalars(select(CVEIngestionSnapshot)).all()
        classifications = session.scalars(select(Classification)).all()
        progress = session.scalar(select(SourceProgress).where(SourceProgress.source_name == "cve.org"))

    assert first.status == "succeeded"
    assert second.status == "noop"
    assert second.checkpoint_before == "2026-04-02T11:00:00+00:00"
    assert second.checkpoint_after == "2026-04-02T11:00:00+00:00"
    assert len(snapshots) == 1
    assert len(classifications) == 1
    assert progress is not None
    assert progress.last_run_status == "NOOP"
    assert progress.cursor == {"last_successful_fetch_time": "2026-04-02T11:00:00+00:00"}


def test_live_poll_no_change_bucket_advances_checkpoint_without_duplicate_work(session_factory) -> None:
    record_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1102.json"
    initial_client = StaticLiveSourceClient(
        [
            _delta_entry(
                "2026-04-02T12:00:00Z",
                [
                    {
                        "cveId": "CVE-2026-1102",
                        "githubLink": record_url,
                        "dateUpdated": "2026-04-02T11:50:00Z",
                    }
                ],
            )
        ],
        {record_url: _record_payload("CVE-2026-1102")},
    )
    advanced_client = StaticLiveSourceClient(
        [
            _delta_entry(
                "2026-04-02T12:00:00Z",
                [
                    {
                        "cveId": "CVE-2026-1102",
                        "githubLink": record_url,
                        "dateUpdated": "2026-04-02T11:50:00Z",
                    }
                ],
            ),
            _delta_entry("2026-04-02T12:10:00Z", []),
        ],
        {record_url: _record_payload("CVE-2026-1102")},
    )

    with session_scope(session_factory) as session:
        first = poll_live_cve_org_feed(session, initial_client, polled_at=datetime(2026, 4, 2, 12, 1, tzinfo=UTC))

    with session_scope(session_factory) as session:
        second = poll_live_cve_org_feed(session, advanced_client, polled_at=datetime(2026, 4, 2, 12, 11, tzinfo=UTC))
        progress = session.scalar(select(SourceProgress).where(SourceProgress.source_name == "cve.org"))
        snapshots = session.scalars(select(CVEIngestionSnapshot)).all()
        cves = session.scalars(select(CVE)).all()

    assert first.status == "succeeded"
    assert second.status == "noop"
    assert second.checkpoint_before == "2026-04-02T12:00:00+00:00"
    assert second.checkpoint_after == "2026-04-02T12:10:00+00:00"
    assert len(snapshots) == 1
    assert len(cves) == 1
    assert progress is not None
    assert progress.cursor == {"last_successful_fetch_time": "2026-04-02T12:10:00+00:00"}


def test_live_poll_records_fetch_or_parse_failures_deterministically(session_factory) -> None:
    bad_record_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1199.json"
    source_client = StaticLiveSourceClient(
        [
            _delta_entry(
                "2026-04-02T13:00:00Z",
                [
                    {
                        "cveId": "CVE-2026-1199",
                        "githubLink": bad_record_url,
                        "dateUpdated": "2026-04-02T12:55:00Z",
                    }
                ],
            )
        ],
        {
            bad_record_url: {
                "cveMetadata": {
                    "cveId": "CVE-2026-1199",
                    "dateUpdated": "2026-04-02T12:55:00Z",
                },
                "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Missing affected section."}]}},
            }
        },
    )

    with session_scope(session_factory) as session:
        result = poll_live_cve_org_feed(session, source_client, polled_at=datetime(2026, 4, 2, 13, 1, tzinfo=UTC))
        progress = session.scalar(select(SourceProgress).where(SourceProgress.source_name == "cve.org"))
        cves = session.scalars(select(CVE)).all()
        audit_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.entity_type == "source_progress")
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()
        metric = _get_metric(
            session,
            LIVE_INGEST_RUN_METRIC_KEY,
            {"failure_stage": "record_adapt", "result": "failed", "source_name": "cve.org"},
        )

    assert result.status == "failed"
    assert result.error_stage == "record_adapt"
    assert result.checkpoint_before is None
    assert result.checkpoint_after is None
    assert progress is not None
    assert progress.cursor == {}
    assert progress.last_run_status == "FAILED"
    assert progress.consecutive_failures == 1
    assert progress.last_error["stage"] == "record_adapt"
    assert len(cves) == 0
    assert sorted(event.event_type for event in audit_events) == ["ingestion.poll_failed", "ingestion.poll_started"]
    assert metric is not None
    assert metric.total_count == 1
    assert metric.last_details["error_stage"] == "record_adapt"


def _delta_entry(fetch_time: str, new_changes: list[dict[str, str]]) -> DeltaEntry:
    return DeltaEntry(
        fetchTime=fetch_time,
        numberOfChanges=len(new_changes),
        new=[DeltaChangePayload(**change) for change in new_changes],
        updated=[],
        error=[],
    )


def _record_payload(cve_id: str) -> dict[str, object]:
    return {
        "cveMetadata": {
            "cveId": cve_id,
            "datePublished": "2026-04-02T09:00:00Z",
            "dateUpdated": "2026-04-02T09:55:00Z",
        },
        "containers": {
            "cna": {
                "title": "Exchange Server RCE",
                "descriptions": [{"lang": "en", "value": "Critical Exchange Server issue."}],
                "affected": [{"vendor": "Microsoft Corporation", "product": "MS Exchange Server"}],
                "metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL"}}],
            }
        },
    }


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
