from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from html import unescape
from typing import Any, Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.core.config import Settings
from cve_service.models.entities import AuditEvent, CVE
from cve_service.models.enums import AuditActorType, CveState
from cve_service.services.evidence_adapters import (
    TrustedItwEvidence,
    TrustedPoCEvidence,
    ingest_trusted_itw_evidence,
    ingest_trusted_poc_evidence,
)
from cve_service.services.state_machine import InvalidStateTransition, guard_transition

ENRICHMENT_SCHEMA_VERSION = "phase7-external-enrichment.v1"
SOURCE_VULNCHECK_KEV = "vulncheck_kev"
SOURCE_EPSS = "epss"
SOURCE_GITHUB_POC = "github_poc"
SOURCE_SEARCHSPLOIT = "searchsploit"
SOURCE_EXPLOITDB = "exploitdb"
GITHUB_ACCEPT_HEADER = "application/vnd.github+json"
EXPLOITDB_AJAX_ACCEPT_HEADER = "application/json, text/javascript, */*; q=0.01"
DEFAULT_USER_AGENT = "cve-service/0.1.0"


@dataclass(frozen=True, slots=True)
class ExternalEnrichmentCheckResult:
    source_name: str
    status: str
    checked_at: datetime
    matched: bool | None
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ExternalEnrichmentResult:
    cve_id: str
    completed_at: datetime | None
    reused: bool
    summary: dict[str, Any]


class SearchSploitRunner(Protocol):
    def search(self, cve_id: str, *, timeout_seconds: float) -> dict[str, Any]:
        """Return the parsed SearchSploit JSON payload for the given CVE."""


@dataclass(frozen=True, slots=True)
class SubprocessSearchSploitRunner:
    binary_path: str = "searchsploit"

    def search(self, cve_id: str, *, timeout_seconds: float) -> dict[str, Any]:
        resolved_binary = shutil.which(self.binary_path) or self.binary_path
        try:
            completed = subprocess.run(
                [resolved_binary, "--json", cve_id],
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"SearchSploit binary was not found: {self.binary_path}") from exc

        stdout = completed.stdout.strip()
        if not stdout:
            if completed.stderr.strip():
                raise RuntimeError(completed.stderr.strip())
            return {}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("SearchSploit returned invalid JSON") from exc


def run_external_enrichment_checks(
    session: Session,
    cve_id: str,
    settings: Settings,
    *,
    client: httpx.Client | None = None,
    searchsploit_runner: SearchSploitRunner | None = None,
    force_refresh: bool = False,
    checked_at: datetime | None = None,
) -> ExternalEnrichmentResult:
    cve = _get_cve_by_public_id(session, cve_id)
    effective_checked_at = _normalize_datetime(checked_at) or datetime.now(UTC)
    existing_summary = cve.external_enrichment or {}

    if not settings.external_enrichment_enabled:
        return ExternalEnrichmentResult(
            cve_id=cve.cve_id,
            completed_at=_parse_datetime(existing_summary.get("completed_at")),
            reused=bool(existing_summary),
            summary=existing_summary,
        )

    state_before = cve.state
    state_after = _start_external_enrichment_state(cve.state)
    if state_after != cve.state:
        cve.state = state_after
        session.flush()

    if not force_refresh and _is_fresh(existing_summary, effective_checked_at):
        _write_audit_event(
            session,
            cve=cve,
            actor_type=AuditActorType.WORKER,
            event_type="workflow.external_enrichment_reused",
            state_before=state_before,
            state_after=cve.state,
            details={
                "checked_at": _serialize_datetime(effective_checked_at),
                "cache_expires_at": existing_summary.get("cache_expires_at"),
                "sources": existing_summary.get("sources", {}),
            },
        )
        return ExternalEnrichmentResult(
            cve_id=cve.cve_id,
            completed_at=_parse_datetime(existing_summary.get("completed_at")),
            reused=True,
            summary=existing_summary,
        )

    _write_audit_event(
        session,
        cve=cve,
        actor_type=AuditActorType.WORKER,
        event_type="workflow.external_enrichment_started",
        state_before=state_before,
        state_after=cve.state,
        details={"checked_at": _serialize_datetime(effective_checked_at)},
    )

    owned_client: httpx.Client | None = None
    active_client = client
    if active_client is None:
        owned_client = httpx.Client(
            timeout=settings.external_enrichment_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        active_client = owned_client

    runner = searchsploit_runner or SubprocessSearchSploitRunner(settings.searchsploit_binary_path)
    try:
        source_results = (
            _run_source_check(
                SOURCE_VULNCHECK_KEV,
                effective_checked_at,
                lambda: _check_vulncheck_kev(session, cve, settings, active_client, effective_checked_at),
            ),
            _run_source_check(
                SOURCE_EPSS,
                effective_checked_at,
                lambda: _check_epss(cve.cve_id, settings, active_client, effective_checked_at),
            ),
            _github_source_result(session, cve, settings, active_client, effective_checked_at),
            _run_source_check(
                SOURCE_SEARCHSPLOIT,
                effective_checked_at,
                lambda: _check_searchsploit(session, cve, settings, runner, effective_checked_at),
            ),
            _run_source_check(
                SOURCE_EXPLOITDB,
                effective_checked_at,
                lambda: _check_exploitdb(session, cve, settings, active_client, effective_checked_at),
            ),
        )
    finally:
        if owned_client is not None:
            owned_client.close()

    summary = _build_summary(
        cve_id=cve.cve_id,
        checked_at=effective_checked_at,
        cache_ttl_seconds=settings.external_enrichment_cache_ttl_seconds,
        source_results=source_results,
    )
    cve.external_enrichment = summary
    session.flush()

    _write_audit_event(
        session,
        cve=cve,
        actor_type=AuditActorType.WORKER,
        event_type="workflow.external_enrichment_completed",
        state_before=cve.state,
        state_after=cve.state,
        details={"external_enrichment": summary},
    )
    return ExternalEnrichmentResult(
        cve_id=cve.cve_id,
        completed_at=effective_checked_at,
        reused=False,
        summary=summary,
    )


def _github_source_result(
    session: Session,
    cve: CVE,
    settings: Settings,
    client: httpx.Client,
    checked_at: datetime,
) -> ExternalEnrichmentCheckResult:
    if not settings.github_poc_enabled:
        return ExternalEnrichmentCheckResult(
            source_name=SOURCE_GITHUB_POC,
            status="skipped_disabled",
            checked_at=checked_at,
            matched=None,
            details={"reason": "github_poc_disabled"},
        )

    return _run_source_check(
        SOURCE_GITHUB_POC,
        checked_at,
        lambda: _check_github_poc(session, cve, settings, client, checked_at),
    )


def _check_vulncheck_kev(
    session: Session,
    cve: CVE,
    settings: Settings,
    client: httpx.Client,
    checked_at: datetime,
) -> ExternalEnrichmentCheckResult:
    if not settings.vulncheck_api_key:
        return ExternalEnrichmentCheckResult(
            source_name=SOURCE_VULNCHECK_KEV,
            status="skipped_unconfigured",
            checked_at=checked_at,
            matched=None,
            details={"reason": "missing_api_key"},
        )

    response = client.get(
        settings.vulncheck_kev_url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {settings.vulncheck_api_key}",
        },
    )
    response.raise_for_status()
    payload = response.json()
    records = payload.get("data") if isinstance(payload, dict) else []
    if not isinstance(records, list):
        raise ValueError("VulnCheck KEV response did not contain a list of records")

    matched_records = [record for record in records if _record_mentions_cve(record, cve.cve_id)]
    for record in matched_records[: settings.external_enrichment_max_matches]:
        record_id = str(record.get("id") or record.get("vc_id") or record.get("catalog_id") or cve.cve_id)
        ingest_trusted_itw_evidence(
            session,
            TrustedItwEvidence(
                cve_id=cve.cve_id,
                source_name="VulnCheck KEV",
                source_record_id=record_id,
                source_url=_as_string(record.get("url") or record.get("source_url") or settings.vulncheck_kev_url),
                observed_at=_parse_datetime(record.get("date_added") or record.get("dateAdded") or record.get("created")),
                collected_at=checked_at,
                confidence=0.98,
                raw_payload=record if isinstance(record, dict) else {"record": record},
            ),
        )

    compact_matches = [
        {
            "record_id": str(record.get("id") or record.get("vc_id") or record.get("catalog_id") or cve.cve_id),
            "title": _as_string(record.get("title") or record.get("name")),
            "date_added": _serialize_datetime(
                _parse_datetime(record.get("date_added") or record.get("dateAdded") or record.get("created"))
            ),
        }
        for record in matched_records[: settings.external_enrichment_max_matches]
        if isinstance(record, dict)
    ]
    return ExternalEnrichmentCheckResult(
        source_name=SOURCE_VULNCHECK_KEV,
        status="completed",
        checked_at=checked_at,
        matched=bool(matched_records),
        details={
            "match_count": len(matched_records),
            "matches": compact_matches,
        },
    )


def _check_epss(
    cve_id: str,
    settings: Settings,
    client: httpx.Client,
    checked_at: datetime,
) -> ExternalEnrichmentCheckResult:
    response = client.get(
        settings.epss_url,
        params={"cve": cve_id},
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("data") if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        raise ValueError("EPSS response did not contain a list of rows")
    row = rows[0] if rows else None
    details = {
        "score": _to_float(row.get("epss")) if isinstance(row, dict) else None,
        "percentile": _to_float(row.get("percentile")) if isinstance(row, dict) else None,
        "date": row.get("date") if isinstance(row, dict) else None,
    }
    return ExternalEnrichmentCheckResult(
        source_name=SOURCE_EPSS,
        status="completed",
        checked_at=checked_at,
        matched=None,
        details=details,
    )


def _check_github_poc(
    session: Session,
    cve: CVE,
    settings: Settings,
    client: httpx.Client,
    checked_at: datetime,
) -> ExternalEnrichmentCheckResult:
    headers = {
        "Accept": GITHUB_ACCEPT_HEADER,
        "X-GitHub-Api-Version": settings.github_api_version,
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    matches_by_url: dict[str, dict[str, Any]] = {}
    query_summaries: list[dict[str, Any]] = []
    for query in (
        f'"{cve.cve_id}" exploit in:file',
        f'"{cve.cve_id}" poc in:file',
    ):
        response = client.get(
            f"{settings.github_api_base_url.rstrip('/')}/search/code",
            params={"q": query, "per_page": settings.external_enrichment_max_matches},
            headers=headers,
        )
        if response.status_code in {401, 403} and not settings.github_token:
            return ExternalEnrichmentCheckResult(
                source_name=SOURCE_GITHUB_POC,
                status="skipped_unconfigured",
                checked_at=checked_at,
                matched=None,
                details={"reason": f"github_status_{response.status_code}"},
            )
        response.raise_for_status()
        payload = response.json()
        items = payload.get("items") if isinstance(payload, dict) else []
        total_count = payload.get("total_count") if isinstance(payload, dict) else None
        query_summaries.append(
            {
                "query": query,
                "total_count": total_count,
            }
        )
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            html_url = _as_string(item.get("html_url"))
            if not html_url:
                continue
            repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            repo_name = _as_string(repository.get("full_name")) or "unknown-repo"
            path = _as_string(item.get("path")) or "unknown-path"
            matches_by_url.setdefault(
                html_url,
                {
                    "repo_name": repo_name,
                    "path": path,
                    "html_url": html_url,
                    "score": item.get("score"),
                    "sha": item.get("sha"),
                },
            )

    matches = list(matches_by_url.values())[: settings.external_enrichment_max_matches]
    for item in matches:
        source_record_id = f"{item['repo_name']}:{item['path']}"
        ingest_trusted_poc_evidence(
            session,
            TrustedPoCEvidence(
                cve_id=cve.cve_id,
                source_name="GitHub Code Search",
                source_record_id=source_record_id,
                source_url=item["html_url"],
                collected_at=checked_at,
                confidence=0.72,
                raw_payload=item,
            ),
        )

    return ExternalEnrichmentCheckResult(
        source_name=SOURCE_GITHUB_POC,
        status="completed",
        checked_at=checked_at,
        matched=bool(matches),
        details={
            "match_count": len(matches_by_url),
            "matches": matches,
            "queries": query_summaries,
        },
    )


def _check_searchsploit(
    session: Session,
    cve: CVE,
    settings: Settings,
    runner: SearchSploitRunner,
    checked_at: datetime,
) -> ExternalEnrichmentCheckResult:
    try:
        payload = runner.search(cve.cve_id, timeout_seconds=settings.external_enrichment_timeout_seconds)
    except FileNotFoundError:
        return ExternalEnrichmentCheckResult(
            source_name=SOURCE_SEARCHSPLOIT,
            status="skipped_unavailable",
            checked_at=checked_at,
            matched=None,
            details={"reason": "binary_not_found"},
        )

    matches = [
        match
        for match in _flatten_searchsploit_matches(payload)
        if _searchsploit_match_mentions_cve(match, cve.cve_id) and not _is_dos_match(match.get("path"), match.get("title"))
    ][: settings.external_enrichment_max_matches]

    for match in matches:
        edb_id = _as_string(match.get("edb_id"))
        source_record_id = edb_id or _as_string(match.get("path")) or _as_string(match.get("title")) or cve.cve_id
        source_url = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None
        ingest_trusted_poc_evidence(
            session,
            TrustedPoCEvidence(
                cve_id=cve.cve_id,
                source_name="SearchSploit",
                source_record_id=source_record_id,
                source_url=source_url,
                collected_at=checked_at,
                confidence=0.82,
                raw_payload=match,
            ),
        )

    return ExternalEnrichmentCheckResult(
        source_name=SOURCE_SEARCHSPLOIT,
        status="completed",
        checked_at=checked_at,
        matched=bool(matches),
        details={
            "match_count": len(matches),
            "matches": matches,
        },
    )


def _check_exploitdb(
    session: Session,
    cve: CVE,
    settings: Settings,
    client: httpx.Client,
    checked_at: datetime,
) -> ExternalEnrichmentCheckResult:
    response = client.get(
        settings.exploitdb_search_url,
        params={
            "cve": cve.cve_id,
            "draw": 1,
            "start": 0,
            "length": settings.external_enrichment_max_matches,
        },
        headers={
            "Accept": EXPLOITDB_AJAX_ACCEPT_HEADER,
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("data") if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        raise ValueError("Exploit-DB response did not contain a list of rows")

    matches: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or not _record_mentions_cve(row, cve.cve_id):
            continue
        title = _exploitdb_title(row)
        if _is_dos_match(_as_string(row.get("type_id")), title):
            continue
        edb_id = _as_string(row.get("id"))
        match = {
            "edb_id": edb_id,
            "title": title,
            "type": _as_string((row.get("type") or {}).get("name")) or _as_string(row.get("type_id")),
            "platform": _as_string((row.get("platform") or {}).get("platform")) or _as_string(row.get("platform_id")),
            "verified": bool(row.get("verified")),
            "source_url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None,
        }
        matches.append(match)

    for match in matches[: settings.external_enrichment_max_matches]:
        source_record_id = match["edb_id"] or match["title"] or cve.cve_id
        ingest_trusted_poc_evidence(
            session,
            TrustedPoCEvidence(
                cve_id=cve.cve_id,
                source_name="Exploit-DB Search",
                source_record_id=source_record_id,
                source_url=match["source_url"],
                collected_at=checked_at,
                confidence=0.85,
                raw_payload=match,
            ),
        )

    return ExternalEnrichmentCheckResult(
        source_name=SOURCE_EXPLOITDB,
        status="completed",
        checked_at=checked_at,
        matched=bool(matches),
        details={
            "match_count": len(matches),
            "matches": matches[: settings.external_enrichment_max_matches],
        },
    )


def _run_source_check(
    source_name: str,
    checked_at: datetime,
    check,
) -> ExternalEnrichmentCheckResult:
    try:
        return check()
    except httpx.HTTPStatusError as exc:
        return ExternalEnrichmentCheckResult(
            source_name=source_name,
            status="error",
            checked_at=checked_at,
            matched=None,
            details={
                "status_code": exc.response.status_code,
                "message": f"http_status_{exc.response.status_code}",
            },
        )
    except httpx.HTTPError as exc:
        return ExternalEnrichmentCheckResult(
            source_name=source_name,
            status="error",
            checked_at=checked_at,
            matched=None,
            details={"message": str(exc)},
        )
    except Exception as exc:
        return ExternalEnrichmentCheckResult(
            source_name=source_name,
            status="error",
            checked_at=checked_at,
            matched=None,
            details={"message": str(exc)},
        )


def _build_summary(
    *,
    cve_id: str,
    checked_at: datetime,
    cache_ttl_seconds: int,
    source_results: tuple[ExternalEnrichmentCheckResult, ...],
) -> dict[str, Any]:
    return {
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "cve_id": cve_id,
        "checked_at": checked_at.isoformat(),
        "completed_at": checked_at.isoformat(),
        "cache_expires_at": (checked_at + timedelta(seconds=cache_ttl_seconds)).isoformat(),
        "sources": {
            result.source_name: _compact_source_status(result)
            for result in source_results
        },
    }


def _compact_source_status(result: ExternalEnrichmentCheckResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "matched": result.matched,
        "checked_at": result.checked_at.isoformat(),
        **result.details,
    }


def _flatten_searchsploit_matches(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    matches: list[dict[str, Any]] = []
    for value in payload.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            title = _case_insensitive_get(item, "title")
            path = _case_insensitive_get(item, "path")
            edb_id = _case_insensitive_get(item, "edb-id")
            if title is None and path is None and edb_id is None:
                continue
            matches.append(
                {
                    "title": _as_string(title),
                    "path": _as_string(path),
                    "edb_id": _as_string(edb_id),
                }
            )
    return matches


def _searchsploit_match_mentions_cve(match: dict[str, Any], cve_id: str) -> bool:
    haystacks = [match.get("title"), match.get("path"), match.get("edb_id")]
    target_full = cve_id.upper()
    target_suffix = cve_id.removeprefix("CVE-").upper()
    return any(
        isinstance(value, str) and (target_full in value.upper() or target_suffix in value.upper())
        for value in haystacks
    )


def _exploitdb_title(row: dict[str, Any]) -> str | None:
    description = row.get("description")
    if isinstance(description, list) and len(description) >= 2:
        return unescape(str(description[1]))
    if isinstance(description, str):
        return unescape(description)
    return None


def _record_mentions_cve(record: dict[str, Any], cve_id: str) -> bool:
    target_full = cve_id.upper()
    target_suffix = cve_id.removeprefix("CVE-").upper()
    for value in record.values():
        if isinstance(value, str) and (target_full in value.upper() or target_suffix in value.upper()):
            return True
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and (target_full in item.upper() or target_suffix in item.upper()):
                    return True
                if isinstance(item, dict):
                    for nested in item.values():
                        if isinstance(nested, str) and (target_full in nested.upper() or target_suffix in nested.upper()):
                            return True
    return False


def _is_dos_match(path: str | None, title: str | None) -> bool:
    normalized_path = (path or "").lower()
    normalized_title = (title or "").lower()
    return "/dos/" in normalized_path or "denial of service" in normalized_title or normalized_path == "dos"


def _is_fresh(summary: dict[str, Any], evaluated_at: datetime) -> bool:
    cache_expires_at = _parse_datetime(summary.get("cache_expires_at"))
    return cache_expires_at is not None and cache_expires_at > evaluated_at


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown cve_id: {cve_id}")
    return cve


def _start_external_enrichment_state(current_state: CveState) -> CveState:
    if current_state in {CveState.CLASSIFIED, CveState.DEFERRED}:
        return _resolve_state(current_state, CveState.ENRICHMENT_PENDING)
    return current_state


def _resolve_state(current_state: CveState, desired_state: CveState) -> CveState:
    if current_state == desired_state:
        return current_state

    try:
        return guard_transition(current_state, desired_state)
    except InvalidStateTransition:
        return current_state


def _write_audit_event(
    session: Session,
    *,
    cve: CVE,
    actor_type: AuditActorType,
    event_type: str,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="workflow",
            entity_id=None,
            actor_type=actor_type,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )


def _case_insensitive_get(payload: dict[str, Any], key: str) -> Any:
    target = key.lower()
    for existing_key, value in payload.items():
        if existing_key.lower() == target:
            return value
    return None


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return _normalize_datetime(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        return _normalize_datetime(datetime.fromisoformat(normalized))
    except ValueError:
        if len(normalized) == 10:
            parsed_date = date.fromisoformat(normalized)
            return datetime(parsed_date.year, parsed_date.month, parsed_date.day, tzinfo=UTC)
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
