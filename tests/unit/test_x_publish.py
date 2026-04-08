from __future__ import annotations

import json

import httpx
import pytest

from cve_service.core.config import Settings
from cve_service.services.publish_content import PublishContent
from cve_service.services.publish_targets import PublishRequest, PublishTargetError
from cve_service.services.x_publish import XPublishTarget, build_x_thread_plan


def test_build_x_thread_plan_keeps_long_initial_payload_in_single_post() -> None:
    request = _initial_request(
        description="Remote code execution " * 80,
        description_brief="Remote code execution " * 80,
    )

    posts = build_x_thread_plan(request)

    assert len(posts) == 1
    assert posts[0].text.count("Remote code execution") >= 80
    assert posts[0].reply_to_post_id is None


def test_build_x_thread_plan_formats_initial_payload_deterministically() -> None:
    request = _initial_request(
        description=(
            "A denial of service vulnerability in Keycloak allows an unauth attacker to send crafted POST requests "
            "to the OIDC token endpoint and exhaust server resources."
        ),
        description_brief=(
            "A denial of service vulnerability in Keycloak allows an unauth attacker to send crafted POST requests "
            "to the OIDC token endpoint and exhaust server resources."
        ),
        primary_product="Keycloak",
        vulnerability_type="Denial of Service",
        severity="High",
        exploitation="No confirmed in-the-wild exploitation",
        public_poc="Unknown",
        patch_available="Yes",
        affected_product="Keycloak",
        affected_version="< 26.1.4",
    )

    posts = build_x_thread_plan(request)
    combined = "\n".join(post.text for post in posts)

    assert combined.startswith("CVE-2026-6100 | Keycloak | Denial of Service")
    assert "Description\nA denial of service vulnerability in Keycloak" in combined
    assert "Severity: High" in combined
    assert "Exploitation: No confirmed in-the-wild exploitation" in combined
    assert "Public PoC: Unknown" in combined
    assert "Patch Available: Yes" in combined
    assert "Affected Product: Keycloak" in combined
    assert "Affected Version: < 26.1.4" in combined
    assert "PoC: n/a" not in combined
    assert "Exploited: n/a" not in combined
    assert "Summary:" not in combined
    assert "Reasons:" not in combined
    assert "Scope:" not in combined


def test_build_x_thread_plan_preserves_literal_escape_sequences() -> None:
    request = _initial_request(
        description=r"Undertow request smuggling via \r\r\r header terminator.",
        description_brief=r"Undertow request smuggling via \r\r\r header terminator.",
    )

    posts = build_x_thread_plan(request)

    assert len(posts) == 1
    assert r"\r\r\r" in posts[0].text
    assert "via r r r" not in posts[0].text


def test_build_x_thread_plan_includes_labeled_reference_links_only_when_present() -> None:
    request = _initial_request(
        reference_links={
            "vendor": [{"url": "https://vendor.example/advisory"}],
            "research": [{"url": "https://research.example/write-up"}],
            "poc": [{"url": "https://github.com/example/repo/blob/main/poc.py"}],
        }
    )

    posts = build_x_thread_plan(request)
    text = posts[0].text

    assert "Sources\nVendor: https://vendor.example/advisory" in text
    assert "Research: https://research.example/write-up" in text
    assert "PoC: https://github.com/example/repo/blob/main/poc.py" in text
    assert "ITW:" not in text


def test_build_x_thread_plan_prefers_poc_link_backed_status_over_unknown_polling_state() -> None:
    request = _initial_request(
        reference_links={
            "poc": [{"url": "https://github.com/example/repo/blob/main/poc.py"}],
        },
        public_poc="Yes",
    )

    posts = build_x_thread_plan(request)
    text = posts[0].text

    assert "Public PoC: Yes" in text
    assert "PoC: n/a" not in text


def test_build_x_thread_plan_omits_mitigations_section_when_no_source_backed_mitigations_exist() -> None:
    request = _initial_request()

    posts = build_x_thread_plan(request)

    assert "Mitigations\n" not in posts[0].text


def test_x_publish_target_posts_update_threads_as_replies() -> None:
    captured_requests: list[dict[str, object]] = []
    response_ids = ["x-post-100"]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        captured_requests.append(payload)
        return httpx.Response(201, json={"data": {"id": response_ids[len(captured_requests) - 1], "text": payload["text"]}})

    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth2_bearer",
        x_bearer_token="test-bearer-token",
    )
    target = XPublishTarget.from_settings(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    response = target.publish(_update_request(baseline_external_id="x-root-42"))

    assert response.external_id == "x-post-100"
    assert response.response_payload["post_ids"][0] == "x-post-100"
    assert len(captured_requests) == 1
    assert captured_requests[0]["reply"] == {"in_reply_to_tweet_id": "x-root-42"}


def test_x_publish_target_maps_rate_limit_failures_as_retryable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={
                "x-rate-limit-limit": "100",
                "x-rate-limit-remaining": "0",
                "retry-after": "45",
            },
            json={"errors": [{"message": "too many requests"}]},
        )

    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth2_bearer",
        x_bearer_token="test-bearer-token",
    )
    target = XPublishTarget.from_settings(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    with pytest.raises(PublishTargetError) as exc_info:
        target.publish(_initial_request())

    error = exc_info.value
    assert error.category == "rate_limited"
    assert error.retryable is True
    assert error.rate_limited is True
    assert error.retry_after_seconds == 45


def test_x_publish_target_maps_permanent_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": [{"message": "forbidden"}]})

    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth2_bearer",
        x_bearer_token="test-bearer-token",
    )
    target = XPublishTarget.from_settings(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    with pytest.raises(PublishTargetError) as exc_info:
        target.publish(_initial_request())

    error = exc_info.value
    assert error.category == "permanent_failure"
    assert error.retryable is False
    assert error.status_code == 403


def test_x_publish_target_uses_oauth1_user_context_headers() -> None:
    captured_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["authorization"] = request.headers["Authorization"]
        return httpx.Response(201, json={"data": {"id": "x-post-201", "text": "ok"}})

    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth1_user",
        x_consumer_key="consumer-key",
        x_consumer_secret="consumer-secret",
        x_access_token="access-token",
        x_access_token_secret="access-token-secret",
    )
    target = XPublishTarget.from_settings(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    response = target.publish(_initial_request())

    assert response.external_id == "x-post-201"
    assert captured_headers["authorization"].startswith("OAuth ")
    assert "oauth_signature=" in captured_headers["authorization"]


def test_x_publish_target_requires_baseline_external_id_for_updates() -> None:
    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth2_bearer",
        x_bearer_token="test-bearer-token",
    )
    target = XPublishTarget.from_settings(
        settings,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(201, json={"data": {"id": "unused"}}))),
    )

    with pytest.raises(PublishTargetError) as exc_info:
        target.publish(_update_request(baseline_external_id=None))

    error = exc_info.value
    assert error.category == "reconciliation_required"
    assert error.requires_reconciliation is True
    assert error.retry_blocked is True


def _initial_request(
    *,
    description: str = "Enterprise Exchange Server RCE with exploit evidence.",
    description_brief: str = (
        "A remote code execution vulnerability in Microsoft Exchange Server allows an unauth attacker "
        "to send crafted requests to exposed Exchange services and execute code."
    ),
    reference_links: dict[str, object] | None = None,
    primary_product: str = "Microsoft Exchange Server",
    vulnerability_type: str = "Remote Code Execution",
    severity: str = "Critical",
    exploitation: str = "Unknown",
    public_poc: str = "Unknown",
    patch_available: str = "Unknown",
    affected_product: str = "Microsoft Exchange Server",
    affected_version: str = "Unknown",
    mitigations: list[str] | None = None,
) -> PublishRequest:
    return PublishRequest(
        cve_id="CVE-2026-6100",
        event_type="INITIAL",
        target_name="x",
        idempotency_key="idempotency-initial-6100",
        content_hash="content-hash-initial-6100",
        content=PublishContent(
            schema_version="phase4-initial-publication.v1",
            title="CVE-2026-6100: Exchange Server RCE",
            summary="CRITICAL | Microsoft Exchange Server | poc",
            body="ignored by x target",
            labels=("severity:critical",),
            metadata={
                "cve_id": "CVE-2026-6100",
                "severity": "CRITICAL",
                "canonical_name": "Microsoft Exchange Server",
                "product_scope": "enterprise",
                "affected_products": ["Microsoft Exchange Server"],
                "poc_status": "UNKNOWN",
                "itw_status": "UNKNOWN",
                "policy_reason_codes": ["policy.publish.enterprise_candidate_with_poc"],
                "reference_links": reference_links or {},
            },
        ),
        payload_snapshot={
            "replay_context": {
                "cve": {
                    "description": description,
                },
                "source_references": {
                    "origin": "cve.org",
                    "links": reference_links or {},
                },
                "description_compression": {
                    "description_brief": description_brief,
                    "source": "llm",
                    "model_name": "x-ai/grok-4.1-fast",
                    "prompt_version": "phase9-description-compression.v1",
                },
                "x_post": {
                    "primary_product": primary_product,
                    "vulnerability_type": vulnerability_type,
                    "description": description_brief,
                    "severity": severity,
                    "exploitation": exploitation,
                    "public_poc": public_poc,
                    "patch_available": patch_available,
                    "affected_product": affected_product,
                    "affected_version": affected_version,
                    "mitigations": mitigations or [],
                },
            }
        },
    )


def _update_request(*, baseline_external_id: str | None) -> PublishRequest:
    return PublishRequest(
        cve_id="CVE-2026-6101",
        event_type="UPDATE",
        target_name="x",
        idempotency_key="idempotency-update-6101",
        content_hash="content-hash-update-6101",
        content=PublishContent(
            schema_version="phase5-update-publication.v1",
            title="CVE-2026-6101 Update: PoC UNKNOWN -> PRESENT",
            summary="CRITICAL | Microsoft Exchange Server | poc:UNKNOWN->PRESENT",
            body="ignored by x target",
            labels=("publication:update",),
            metadata={
                "severity": "CRITICAL",
                "canonical_name": "Microsoft Exchange Server",
                "product_scope": "enterprise",
                "reason_codes": ["update.material_change.evidence.poc_status"],
                "material_changes": [
                    {"field": "evidence.poc_status", "before": "UNKNOWN", "after": "PRESENT"},
                    {"field": "evidence.itw_status", "before": "UNKNOWN", "after": "PRESENT"},
                    {"field": "details.description", "before": "old", "after": "new"},
                    {"field": "details.proof", "before": "none", "after": "public"},
                ],
                "baseline_evidence": {
                    "poc": {"status": "UNKNOWN", "confidence": None},
                    "itw": {"status": "UNKNOWN", "confidence": None},
                },
                "current_evidence": {
                    "poc": {"status": "PRESENT", "confidence": 0.98},
                    "itw": {"status": "PRESENT", "confidence": 0.91},
                },
            },
        ),
        payload_snapshot={
            "replay_context": {
                "baseline_publication": {
                    "id": "baseline-event-6101",
                    "destination": "x",
                    "external_id": baseline_external_id,
                }
            }
        },
    )
