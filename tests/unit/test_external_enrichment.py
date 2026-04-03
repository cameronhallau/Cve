from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx

from cve_service.models.entities import CVE
from cve_service.models.enums import CveState
from cve_service.services.external_enrichment import (
    SOURCE_EPSS,
    SOURCE_EXPLOITDB,
    SOURCE_GITHUB_POC,
    SOURCE_SEARCHSPLOIT,
    SOURCE_VULNCHECK_KEV,
    run_external_enrichment_checks,
)


class FakeSession:
    def __init__(self) -> None:
        self.flush_count = 0
        self.audit_events = []

    def flush(self) -> None:
        self.flush_count += 1

    def add(self, item) -> None:
        self.audit_events.append(item)


class FakeSearchSploitRunner:
    def search(self, cve_id: str, *, timeout_seconds: float) -> dict[str, object]:
        assert cve_id == "CVE-2026-7777"
        assert timeout_seconds == 8.0
        return {
            "RESULTS_EXPLOIT": [
                {
                    "Title": "Widget Suite - CVE-2026-7777 public exploit",
                    "EDB-ID": "60001",
                    "Path": "exploits/multiple/remote/60001.py",
                }
            ]
        }


def test_run_external_enrichment_checks_persists_summary_and_ingests_positive_matches(monkeypatch) -> None:
    checked_at = datetime(2026, 4, 3, 4, 0, tzinfo=UTC)
    cve = CVE(
        id=uuid4(),
        cve_id="CVE-2026-7777",
        title="Widget Suite RCE",
        description="Remote code execution in Widget Suite.",
        severity="CRITICAL",
        state=CveState.CLASSIFIED,
        external_enrichment={},
    )
    session = FakeSession()
    captured_itw = []
    captured_poc = []

    def mock_get_cve_by_public_id(_session, cve_id: str) -> CVE:
        assert cve_id == "CVE-2026-7777"
        return cve

    def mock_ingest_itw(_session, evidence) -> None:
        captured_itw.append(evidence)

    def mock_ingest_poc(_session, evidence) -> None:
        captured_poc.append(evidence)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/vulncheck-kev"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "vc-1",
                            "cve": ["CVE-2026-7777"],
                            "title": "Widget Suite exploitation activity",
                            "date_added": "2026-04-03T01:00:00Z",
                        }
                    ]
                },
            )
        if request.url.path.endswith("/epss"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "cve": "CVE-2026-7777",
                            "epss": "0.9300",
                            "percentile": "0.9910",
                            "date": "2026-04-03",
                        }
                    ]
                },
            )
        if request.url.path.endswith("/search/code"):
            query = request.url.params["q"]
            if "exploit" in query:
                return httpx.Response(
                    200,
                    json={
                        "total_count": 1,
                        "items": [
                            {
                                "html_url": "https://github.com/acme/widget-poc/blob/main/exploit.py",
                                "path": "exploit.py",
                                "sha": "abc123",
                                "score": 42.0,
                                "repository": {"full_name": "acme/widget-poc"},
                            }
                        ],
                    },
                )
            return httpx.Response(200, json={"total_count": 0, "items": []})
        if request.url.host == "www.exploit-db.com":
            return httpx.Response(
                200,
                json={
                    "draw": 1,
                    "recordsTotal": 1,
                    "recordsFiltered": 1,
                    "data": [
                        {
                            "id": "50383",
                            "description": ["50383", "Widget Suite 9.9 - Remote Code Execution"],
                            "type_id": "webapps",
                            "platform_id": "Multiple",
                            "verified": 1,
                            "type": {"name": "webapps"},
                            "platform": {"platform": "Multiple"},
                            "code": [{"code_type": "cve", "code": "2026-7777"}],
                        }
                    ],
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    settings = SimpleNamespace(
        external_enrichment_enabled=True,
        external_enrichment_timeout_seconds=8.0,
        external_enrichment_cache_ttl_seconds=3600,
        external_enrichment_max_matches=5,
        vulncheck_kev_url="https://api.vulncheck.com/v3/backup/vulncheck-kev",
        vulncheck_api_key="vulncheck-token",
        epss_url="https://api.first.org/data/v1/epss",
        github_poc_enabled=True,
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_token="github-token",
        searchsploit_binary_path="searchsploit",
        exploitdb_search_url="https://www.exploit-db.com/search",
    )

    monkeypatch.setattr(
        "cve_service.services.external_enrichment._get_cve_by_public_id",
        mock_get_cve_by_public_id,
    )
    monkeypatch.setattr(
        "cve_service.services.external_enrichment.ingest_trusted_itw_evidence",
        mock_ingest_itw,
    )
    monkeypatch.setattr(
        "cve_service.services.external_enrichment.ingest_trusted_poc_evidence",
        mock_ingest_poc,
    )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = run_external_enrichment_checks(
            session,
            "CVE-2026-7777",
            settings,
            client=client,
            searchsploit_runner=FakeSearchSploitRunner(),
            checked_at=checked_at,
        )
    finally:
        client.close()

    assert result.reused is False
    assert result.completed_at == checked_at
    assert cve.state is CveState.ENRICHMENT_PENDING
    assert len(captured_itw) == 1
    assert len(captured_poc) == 3
    assert cve.external_enrichment["schema_version"] == "phase7-external-enrichment.v1"
    assert cve.external_enrichment["cache_expires_at"] == (checked_at + timedelta(hours=1)).isoformat()
    assert cve.external_enrichment["sources"][SOURCE_VULNCHECK_KEV]["matched"] is True
    assert cve.external_enrichment["sources"][SOURCE_EPSS]["score"] == 0.93
    assert cve.external_enrichment["sources"][SOURCE_GITHUB_POC]["match_count"] == 1
    assert cve.external_enrichment["sources"][SOURCE_SEARCHSPLOIT]["match_count"] == 1
    assert cve.external_enrichment["sources"][SOURCE_EXPLOITDB]["match_count"] == 1


def test_run_external_enrichment_checks_reuses_fresh_cached_summary(monkeypatch) -> None:
    checked_at = datetime(2026, 4, 3, 5, 0, tzinfo=UTC)
    cve = CVE(
        id=uuid4(),
        cve_id="CVE-2026-8888",
        title="Cached Widget issue",
        description="Cached external enrichment summary.",
        severity="HIGH",
        state=CveState.DEFERRED,
        external_enrichment={
            "schema_version": "phase7-external-enrichment.v1",
            "completed_at": "2026-04-03T04:00:00+00:00",
            "cache_expires_at": "2026-04-03T06:00:00+00:00",
            "sources": {
                SOURCE_EPSS: {
                    "status": "completed",
                    "score": 0.45,
                }
            },
        },
    )
    session = FakeSession()

    def mock_get_cve_by_public_id(_session, cve_id: str) -> CVE:
        assert cve_id == "CVE-2026-8888"
        return cve

    monkeypatch.setattr(
        "cve_service.services.external_enrichment._get_cve_by_public_id",
        mock_get_cve_by_public_id,
    )

    settings = SimpleNamespace(
        external_enrichment_enabled=True,
        external_enrichment_timeout_seconds=8.0,
        external_enrichment_cache_ttl_seconds=3600,
        external_enrichment_max_matches=5,
        vulncheck_kev_url="https://api.vulncheck.com/v3/backup/vulncheck-kev",
        vulncheck_api_key=None,
        epss_url="https://api.first.org/data/v1/epss",
        github_poc_enabled=False,
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_token=None,
        searchsploit_binary_path="searchsploit",
        exploitdb_search_url="https://www.exploit-db.com/search",
    )

    result = run_external_enrichment_checks(
        session,
        "CVE-2026-8888",
        settings,
        checked_at=checked_at,
    )

    assert result.reused is True
    assert result.summary == cve.external_enrichment
    assert result.completed_at == datetime(2026, 4, 3, 4, 0, tzinfo=UTC)


def test_run_external_enrichment_checks_skips_github_when_disabled(monkeypatch) -> None:
    checked_at = datetime(2026, 4, 3, 6, 0, tzinfo=UTC)
    cve = CVE(
        id=uuid4(),
        cve_id="CVE-2026-9999",
        title="SearchSploit-only check",
        description="GitHub PoC disabled.",
        severity="HIGH",
        state=CveState.CLASSIFIED,
        external_enrichment={},
    )
    session = FakeSession()
    captured_poc = []

    def mock_get_cve_by_public_id(_session, cve_id: str) -> CVE:
        assert cve_id == "CVE-2026-9999"
        return cve

    def mock_ingest_poc(_session, evidence) -> None:
        captured_poc.append(evidence)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/epss"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "cve": "CVE-2026-9999",
                            "epss": "0.4400",
                            "percentile": "0.5500",
                            "date": "2026-04-03",
                        }
                    ]
                },
            )
        if request.url.host == "www.exploit-db.com":
            return httpx.Response(200, json={"draw": 1, "recordsTotal": 0, "recordsFiltered": 0, "data": []})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    settings = SimpleNamespace(
        external_enrichment_enabled=True,
        external_enrichment_timeout_seconds=8.0,
        external_enrichment_cache_ttl_seconds=3600,
        external_enrichment_max_matches=5,
        vulncheck_kev_url="https://api.vulncheck.com/v3/backup/vulncheck-kev",
        vulncheck_api_key=None,
        epss_url="https://api.first.org/data/v1/epss",
        github_poc_enabled=False,
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_token=None,
        searchsploit_binary_path="searchsploit",
        exploitdb_search_url="https://www.exploit-db.com/search",
    )

    monkeypatch.setattr(
        "cve_service.services.external_enrichment._get_cve_by_public_id",
        mock_get_cve_by_public_id,
    )
    monkeypatch.setattr(
        "cve_service.services.external_enrichment.ingest_trusted_poc_evidence",
        mock_ingest_poc,
    )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = run_external_enrichment_checks(
            session,
            "CVE-2026-9999",
            settings,
            client=client,
            checked_at=checked_at,
        )
    finally:
        client.close()

    assert result.reused is False
    assert captured_poc == []
    assert result.summary["sources"][SOURCE_GITHUB_POC]["status"] == "skipped_disabled"
    assert result.summary["sources"][SOURCE_GITHUB_POC]["reason"] == "github_poc_disabled"
