from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AuditEvent, SourceProgress
from cve_service.models.enums import AuditActorType
from cve_service.services.alerting import evaluate_operational_alerts
from cve_service.services.ingestion import IngestionResult, ingest_public_feed_record
from cve_service.services.operational_metrics import increment_operational_metric
from cve_service.services.post_enrichment_queue import PostEnrichmentJobProducer
from cve_service.services.public_feed import CveOrgRecordAdapter

LIVE_INGEST_SOURCE_NAME = "cve.org"
LIVE_INGEST_RUN_METRIC_KEY = "phase6.ingest_poll.runs.total"
LIVE_INGEST_CURSOR_KEY = "last_successful_fetch_time"
DELTA_LOG_ALLOWED_HOSTS = {"raw.githubusercontent.com"}
RECORD_ALLOWED_HOSTS = {"raw.githubusercontent.com"}


@dataclass(frozen=True, slots=True)
class LiveIngestionPollResult:
    source_name: str
    status: str
    started_at: datetime
    completed_at: datetime
    checkpoint_before: str | None
    checkpoint_after: str | None
    delta_entries_seen: int
    delta_entries_applied: int
    unique_changes_seen: int
    records_fetched: int
    ingested_records: int
    snapshots_created: int
    classifications_created: int
    post_enrichment_jobs: tuple[str, ...]
    upstream_error_count: int
    error_stage: str | None = None
    error_message: str | None = None
    error_details: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class DeltaChange:
    cve_id: str
    github_link: str
    date_updated: datetime | None
    change_kind: str
    source_fetch_time: datetime


class LiveSourceClient(Protocol):
    def fetch_delta_entries(self) -> list["DeltaEntry"]:
        """Fetch upstream delta log entries."""

    def fetch_record(self, record_url: str) -> dict[str, Any]:
        """Fetch a single upstream CVE record payload."""


class DeltaChangePayload(BaseModel):
    cve_id: str = Field(alias="cveId")
    github_link: str = Field(alias="githubLink")
    date_updated: datetime | None = Field(default=None, alias="dateUpdated")


class DeltaEntry(BaseModel):
    fetch_time: datetime = Field(alias="fetchTime")
    number_of_changes: int = Field(default=0, alias="numberOfChanges")
    new: list[DeltaChangePayload] = Field(default_factory=list)
    updated: list[DeltaChangePayload] = Field(default_factory=list)
    error: list[Any] = Field(default_factory=list)


class LivePollError(RuntimeError):
    def __init__(self, stage: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.details = details or {}


@dataclass
class CveOrgDeltaLogClient:
    delta_log_url: str
    timeout_seconds: float = 20.0
    user_agent: str = "cve-service/0.1.0"
    client: httpx.Client | None = None
    _owned_client: httpx.Client | None = None

    def fetch_delta_entries(self) -> list[DeltaEntry]:
        payload = self._fetch_json(self.delta_log_url, stage="delta_log_fetch", allowed_hosts=DELTA_LOG_ALLOWED_HOSTS)
        try:
            entries = TypeAdapter(list[DeltaEntry]).validate_python(payload)
        except ValidationError as exc:
            raise LivePollError(
                "delta_log_parse",
                "failed to parse the upstream delta log payload",
                details={"url": self.delta_log_url, "validation_error_count": len(exc.errors())},
            ) from exc
        return sorted(entries, key=lambda entry: _normalize_datetime(entry.fetch_time))

    def fetch_record(self, record_url: str) -> dict[str, Any]:
        payload = self._fetch_json(record_url, stage="record_fetch", allowed_hosts=RECORD_ALLOWED_HOSTS)
        if not isinstance(payload, dict):
            raise LivePollError(
                "record_parse",
                "upstream record payload must be a JSON object",
                details={"record_url": record_url},
            )
        return payload

    @property
    def _http_client(self) -> httpx.Client:
        if self.client is not None:
            return self.client
        if self._owned_client is None:
            self._owned_client = httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=True,
                headers={"User-Agent": self.user_agent},
            )
        return self._owned_client

    def _fetch_json(self, url: str, *, stage: str, allowed_hosts: set[str]) -> Any:
        _validate_url(url, allowed_hosts=allowed_hosts, stage=stage)
        try:
            response = self._http_client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            raise LivePollError(
                stage,
                f"upstream request failed with status {exc.response.status_code}",
                details={"url": url, "status_code": exc.response.status_code},
            ) from exc
        except httpx.HTTPError as exc:
            raise LivePollError(stage, f"upstream request failed: {exc}", details={"url": url}) from exc
        except ValueError as exc:
            raise LivePollError(stage, "upstream response was not valid JSON", details={"url": url}) from exc


def poll_live_cve_org_feed(
    session: Session,
    source_client: LiveSourceClient,
    *,
    source_name: str = LIVE_INGEST_SOURCE_NAME,
    adapter: CveOrgRecordAdapter | None = None,
    post_enrichment_producer: PostEnrichmentJobProducer | None = None,
    polled_at: datetime | None = None,
) -> LiveIngestionPollResult:
    effective_polled_at = _normalize_datetime(polled_at) or datetime.now(UTC)
    progress = _get_or_create_source_progress(session, source_name)
    adapter_instance = adapter or CveOrgRecordAdapter(source_name=source_name)
    checkpoint_before = _cursor_value(progress.cursor)
    checkpoint_before_dt = _cursor_datetime(progress.cursor)
    progress.last_poll_started_at = effective_polled_at
    progress.last_run_status = "IN_PROGRESS"
    progress.last_error = {}
    progress.last_run_details = {
        "checkpoint_before": checkpoint_before,
        "started_at": effective_polled_at.isoformat(),
    }
    session.flush()

    _write_source_audit_event(
        session,
        progress=progress,
        event_type="ingestion.poll_started",
        details={
            "source_name": source_name,
            "checkpoint_before": checkpoint_before,
            "started_at": effective_polled_at.isoformat(),
        },
    )

    try:
        delta_entries = source_client.fetch_delta_entries()
        latest_upstream_fetch_at = delta_entries[-1].fetch_time if delta_entries else None
        progress.last_seen_upstream_fetch_at = _normalize_datetime(latest_upstream_fetch_at)

        candidate_entries = [
            entry
            for entry in delta_entries
            if checkpoint_before_dt is None or _normalize_datetime(entry.fetch_time) > checkpoint_before_dt
        ]
        upstream_error_count = sum(len(entry.error) for entry in candidate_entries)

        if not candidate_entries:
            result = _finalize_poll_success(
                session,
                progress=progress,
                source_name=source_name,
                status="noop",
                started_at=effective_polled_at,
                completed_at=effective_polled_at,
                checkpoint_before=checkpoint_before,
                checkpoint_after=checkpoint_before,
                delta_entries_seen=len(delta_entries),
                delta_entries_applied=0,
                unique_changes_seen=0,
                records_fetched=0,
                ingestion_results=[],
                post_enrichment_jobs=[],
                upstream_error_count=0,
            )
            return result

        collapsed_changes = _collapse_changes(candidate_entries)
        completed_at = effective_polled_at

        if not collapsed_changes:
            checkpoint_after = _serialize_datetime(candidate_entries[-1].fetch_time)
            result = _finalize_poll_success(
                session,
                progress=progress,
                source_name=source_name,
                status="noop",
                started_at=effective_polled_at,
                completed_at=completed_at,
                checkpoint_before=checkpoint_before,
                checkpoint_after=checkpoint_after,
                delta_entries_seen=len(delta_entries),
                delta_entries_applied=len(candidate_entries),
                unique_changes_seen=0,
                records_fetched=0,
                ingestion_results=[],
                post_enrichment_jobs=[],
                upstream_error_count=upstream_error_count,
            )
            return result

        ingestion_results: list[IngestionResult] = []
        post_enrichment_jobs: list[str] = []
        for change in collapsed_changes:
            raw_record = source_client.fetch_record(change.github_link)
            try:
                record = adapter_instance.adapt(raw_record)
            except (ValidationError, ValueError, KeyError) as exc:
                raise LivePollError(
                    "record_adapt",
                    f"failed to adapt upstream CVE record {change.cve_id}",
                    details={"cve_id": change.cve_id, "record_url": change.github_link},
                ) from exc
            result = ingest_public_feed_record(session, record)
            ingestion_results.append(result)
            if post_enrichment_producer is not None and result.classification_created:
                job_id = post_enrichment_producer.schedule(
                    session,
                    result.cve_id,
                    trigger="ingestion.live_poll",
                    requested_at=change.date_updated or change.source_fetch_time,
                    evaluated_at=change.date_updated or change.source_fetch_time,
                )
                if job_id is not None:
                    post_enrichment_jobs.append(job_id)

        completed_at = datetime.now(UTC)
        checkpoint_after = _serialize_datetime(candidate_entries[-1].fetch_time)
        return _finalize_poll_success(
            session,
            progress=progress,
            source_name=source_name,
            status="succeeded",
            started_at=effective_polled_at,
            completed_at=completed_at,
            checkpoint_before=checkpoint_before,
            checkpoint_after=checkpoint_after,
            delta_entries_seen=len(delta_entries),
            delta_entries_applied=len(candidate_entries),
            unique_changes_seen=len(collapsed_changes),
            records_fetched=len(collapsed_changes),
            ingestion_results=ingestion_results,
            post_enrichment_jobs=post_enrichment_jobs,
            upstream_error_count=upstream_error_count,
        )
    except LivePollError as exc:
        return _finalize_poll_failure(
            session,
            progress=progress,
            source_name=source_name,
            started_at=effective_polled_at,
            completed_at=datetime.now(UTC),
            checkpoint_before=checkpoint_before,
            error_stage=exc.stage,
            error_message=str(exc),
            error_details=exc.details,
        )
    except Exception as exc:  # pragma: no cover - defensive failure recording
        return _finalize_poll_failure(
            session,
            progress=progress,
            source_name=source_name,
            started_at=effective_polled_at,
            completed_at=datetime.now(UTC),
            checkpoint_before=checkpoint_before,
            error_stage="internal",
            error_message=str(exc),
            error_details={"exception_type": exc.__class__.__name__},
        )


def _finalize_poll_success(
    session: Session,
    *,
    progress: SourceProgress,
    source_name: str,
    status: str,
    started_at: datetime,
    completed_at: datetime,
    checkpoint_before: str | None,
    checkpoint_after: str | None,
    delta_entries_seen: int,
    delta_entries_applied: int,
    unique_changes_seen: int,
    records_fetched: int,
    ingestion_results: list[IngestionResult],
    post_enrichment_jobs: list[str],
    upstream_error_count: int,
) -> LiveIngestionPollResult:
    snapshots_created = sum(1 for result in ingestion_results if result.snapshot_created)
    classifications_created = sum(1 for result in ingestion_results if result.classification_created)
    ingested_records = len(ingestion_results)
    progress.cursor = {LIVE_INGEST_CURSOR_KEY: checkpoint_after} if checkpoint_after is not None else dict(progress.cursor)
    progress.last_poll_completed_at = completed_at
    progress.last_successful_poll_at = completed_at
    progress.last_run_status = status.upper()
    progress.consecutive_failures = 0
    progress.last_error = {}
    progress.last_run_details = {
        "checkpoint_before": checkpoint_before,
        "checkpoint_after": checkpoint_after,
        "delta_entries_seen": delta_entries_seen,
        "delta_entries_applied": delta_entries_applied,
        "unique_changes_seen": unique_changes_seen,
        "records_fetched": records_fetched,
        "ingested_records": ingested_records,
        "snapshots_created": snapshots_created,
        "classifications_created": classifications_created,
        "post_enrichment_jobs": list(post_enrichment_jobs),
        "upstream_error_count": upstream_error_count,
        "completed_at": completed_at.isoformat(),
    }
    session.flush()

    result = LiveIngestionPollResult(
        source_name=source_name,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        checkpoint_before=checkpoint_before,
        checkpoint_after=checkpoint_after,
        delta_entries_seen=delta_entries_seen,
        delta_entries_applied=delta_entries_applied,
        unique_changes_seen=unique_changes_seen,
        records_fetched=records_fetched,
        ingested_records=ingested_records,
        snapshots_created=snapshots_created,
        classifications_created=classifications_created,
        post_enrichment_jobs=tuple(post_enrichment_jobs),
        upstream_error_count=upstream_error_count,
    )
    event_type = "ingestion.poll_no_change" if status == "noop" else "ingestion.poll_succeeded"
    _write_source_audit_event(
        session,
        progress=progress,
        event_type=event_type,
        details=_result_details(result),
    )
    _record_run_metric(session, result)
    evaluate_operational_alerts(session, evaluated_at=completed_at, trigger=f"ingestion.live_poll.{status}")
    return result


def _finalize_poll_failure(
    session: Session,
    *,
    progress: SourceProgress,
    source_name: str,
    started_at: datetime,
    completed_at: datetime,
    checkpoint_before: str | None,
    error_stage: str,
    error_message: str,
    error_details: dict[str, Any],
) -> LiveIngestionPollResult:
    progress.last_poll_completed_at = completed_at
    progress.last_run_status = "FAILED"
    progress.consecutive_failures += 1
    progress.last_error = {
        "stage": error_stage,
        "message": error_message,
        **error_details,
    }
    progress.last_run_details = {
        "checkpoint_before": checkpoint_before,
        "checkpoint_after": checkpoint_before,
        "completed_at": completed_at.isoformat(),
        "error_stage": error_stage,
        "error_message": error_message,
        **error_details,
    }
    session.flush()

    result = LiveIngestionPollResult(
        source_name=source_name,
        status="failed",
        started_at=started_at,
        completed_at=completed_at,
        checkpoint_before=checkpoint_before,
        checkpoint_after=checkpoint_before,
        delta_entries_seen=0,
        delta_entries_applied=0,
        unique_changes_seen=0,
        records_fetched=0,
        ingested_records=0,
        snapshots_created=0,
        classifications_created=0,
        post_enrichment_jobs=(),
        upstream_error_count=0,
        error_stage=error_stage,
        error_message=error_message,
        error_details=error_details,
    )
    _write_source_audit_event(
        session,
        progress=progress,
        event_type="ingestion.poll_failed",
        details=_result_details(result),
    )
    _record_run_metric(session, result)
    evaluate_operational_alerts(session, evaluated_at=completed_at, trigger="ingestion.live_poll.failed")
    return result


def _collapse_changes(entries: list[DeltaEntry]) -> list[DeltaChange]:
    latest_by_cve_id: dict[str, DeltaChange] = {}
    for entry in entries:
        for change_kind, changes in (("new", entry.new), ("updated", entry.updated)):
            for change in changes:
                candidate = DeltaChange(
                    cve_id=change.cve_id,
                    github_link=change.github_link,
                    date_updated=_normalize_datetime(change.date_updated),
                    change_kind=change_kind,
                    source_fetch_time=_normalize_datetime(entry.fetch_time),
                )
                existing = latest_by_cve_id.get(candidate.cve_id)
                if existing is None or _change_sort_key(candidate) >= _change_sort_key(existing):
                    latest_by_cve_id[candidate.cve_id] = candidate
    return sorted(latest_by_cve_id.values(), key=_change_sort_key)


def _change_sort_key(change: DeltaChange) -> tuple[datetime, str]:
    return (change.date_updated or change.source_fetch_time, change.cve_id)


def _get_or_create_source_progress(session: Session, source_name: str) -> SourceProgress:
    progress = session.scalar(
        select(SourceProgress).where(SourceProgress.source_name == source_name).limit(1)
    )
    if progress is not None:
        return progress
    progress = SourceProgress(
        source_name=source_name,
        cursor={},
        last_error={},
        last_run_details={},
        consecutive_failures=0,
    )
    session.add(progress)
    session.flush()
    return progress


def _write_source_audit_event(
    session: Session,
    *,
    progress: SourceProgress,
    event_type: str,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=None,
            entity_type="source_progress",
            entity_id=progress.id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            event_type=event_type,
            state_before=None,
            state_after=None,
            details=details,
        )
    )


def _record_run_metric(session: Session, result: LiveIngestionPollResult) -> None:
    increment_operational_metric(
        session,
        LIVE_INGEST_RUN_METRIC_KEY,
        dimensions={
            "source_name": result.source_name,
            "result": result.status,
            "failure_stage": result.error_stage or "none",
        },
        observed_at=result.completed_at,
        details=_result_details(result),
    )


def _result_details(result: LiveIngestionPollResult) -> dict[str, Any]:
    return {
        "source_name": result.source_name,
        "status": result.status,
        "checkpoint_before": result.checkpoint_before,
        "checkpoint_after": result.checkpoint_after,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat(),
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


def _cursor_value(cursor: dict[str, Any]) -> str | None:
    value = cursor.get(LIVE_INGEST_CURSOR_KEY)
    return str(value) if value else None


def _cursor_datetime(cursor: dict[str, Any]) -> datetime | None:
    value = _cursor_value(cursor)
    return datetime.fromisoformat(value) if value is not None else None


def _serialize_datetime(value: datetime | None) -> str | None:
    normalized = _normalize_datetime(value)
    return normalized.isoformat() if normalized is not None else None


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _validate_url(url: str, *, allowed_hosts: set[str], stage: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise LivePollError(
            stage,
            "upstream URL did not match the allowed host policy",
            details={"url": url, "allowed_hosts": sorted(allowed_hosts)},
        )
