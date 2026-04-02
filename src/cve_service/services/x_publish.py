from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from cve_service.core.config import Settings
from cve_service.services.publish_targets import PublishRequest, PublishResponse, PublishTargetError

X_CREATE_POST_PATH = "/2/tweets"
X_MAX_WEIGHTED_LENGTH = 280
X_MAX_THREAD_POSTS = 4
_X_POST_INDEX_RESERVE = len(f"\n\n{X_MAX_THREAD_POSTS}/{X_MAX_THREAD_POSTS}")


class XAuthStrategy(Protocol):
    def headers(self, method: str, url: str) -> dict[str, str]:
        """Build the auth headers for an X API request."""


@dataclass(frozen=True, slots=True)
class XOAuth2BearerAuth:
    bearer_token: str

    def headers(self, method: str, url: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.bearer_token}"}


@dataclass(frozen=True, slots=True)
class XOAuth1UserAuth:
    consumer_key: str
    consumer_secret: str
    access_token: str
    access_token_secret: str

    def headers(self, method: str, url: str) -> dict[str, str]:
        oauth_params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": token_urlsafe(18),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_token": self.access_token,
            "oauth_version": "1.0",
        }
        signature_base = _build_signature_base_string(method, url, oauth_params)
        signing_key = (
            f"{_percent_encode(self.consumer_secret)}&{_percent_encode(self.access_token_secret)}"
        ).encode("utf-8")
        signature = base64.b64encode(
            hmac.new(signing_key, signature_base.encode("utf-8"), hashlib.sha1).digest()
        ).decode("ascii")
        oauth_params["oauth_signature"] = signature
        return {
            "Authorization": "OAuth "
            + ", ".join(
                f'{_percent_encode(key)}="{_percent_encode(value)}"'
                for key, value in sorted(oauth_params.items())
            )
        }


@dataclass(frozen=True, slots=True)
class XThreadPost:
    text: str
    reply_to_post_id: str | None = None


@dataclass
class XApiClient:
    base_url: str
    timeout_seconds: float
    auth: XAuthStrategy
    client: httpx.Client | None = None

    def create_post(self, *, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{X_CREATE_POST_PATH}"
        headers = {
            "Content-Type": "application/json",
            **self.auth.headers("POST", url),
        }
        try:
            response = self._client.post(url, headers=headers, json=body)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as exc:
            raise PublishTargetError(
                "X publish outcome is unknown after a transport error; reconcile before retrying",
                category="reconciliation_required",
                retryable=False,
                requires_reconciliation=True,
                retry_blocked=True,
                response_payload={
                    "transport_error": exc.__class__.__name__,
                    "request_body": body,
                },
            ) from exc

        response_payload = {
            "request_body": body,
            "response_body": _safe_json(response),
            "rate_limit": _extract_rate_limit_details(response),
        }
        if response.status_code == 429:
            rate_limit = response_payload["rate_limit"]
            raise PublishTargetError(
                "X publish was rate limited",
                category="rate_limited",
                retryable=True,
                rate_limited=True,
                retry_after_seconds=rate_limit.get("retry_after_seconds"),
                status_code=response.status_code,
                response_payload=response_payload,
            )
        if response.status_code >= 500:
            raise PublishTargetError(
                f"X publish failed with retryable server error {response.status_code}",
                category="retryable_failure",
                retryable=True,
                status_code=response.status_code,
                response_payload=response_payload,
            )
        if response.status_code >= 400:
            raise PublishTargetError(
                f"X publish failed with permanent client error {response.status_code}",
                category="permanent_failure",
                retryable=False,
                status_code=response.status_code,
                response_payload=response_payload,
            )

        body_json = _safe_json(response)
        data = body_json.get("data")
        post_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(post_id, str) or not post_id:
            raise PublishTargetError(
                "X publish response did not include a post id",
                category="permanent_failure",
                retryable=False,
                status_code=response.status_code,
                response_payload=response_payload,
            )
        return {
            "id": post_id,
            "response_body": body_json,
            "rate_limit": response_payload["rate_limit"],
        }

    @property
    def _client(self) -> httpx.Client:
        if self.client is not None:
            return self.client
        return httpx.Client(timeout=self.timeout_seconds)


@dataclass
class XPublishTarget:
    api_client: XApiClient
    name: str = "x"

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        client: httpx.Client | None = None,
    ) -> XPublishTarget:
        if settings.x_auth_mode == "oauth1_user":
            auth: XAuthStrategy = XOAuth1UserAuth(
                consumer_key=settings.x_consumer_key or "",
                consumer_secret=settings.x_consumer_secret or "",
                access_token=settings.x_access_token or "",
                access_token_secret=settings.x_access_token_secret or "",
            )
        elif settings.x_auth_mode == "oauth2_bearer":
            auth = XOAuth2BearerAuth(bearer_token=settings.x_bearer_token or "")
        else:  # pragma: no cover - guarded by Settings validation
            raise ValueError(f"unsupported X auth mode: {settings.x_auth_mode}")
        return cls(
            api_client=XApiClient(
                base_url=settings.x_api_base_url,
                timeout_seconds=settings.x_timeout_seconds,
                auth=auth,
                client=client,
            )
        )

    def publish(self, request: PublishRequest) -> PublishResponse:
        planned_posts = build_x_thread_plan(request)
        created_posts: list[dict[str, Any]] = []
        request_bodies: list[dict[str, Any]] = []
        initial_reply_target = planned_posts[0].reply_to_post_id

        try:
            for planned_post in planned_posts:
                request_body = {"text": planned_post.text}
                if planned_post.reply_to_post_id is not None:
                    request_body["reply"] = {"in_reply_to_tweet_id": planned_post.reply_to_post_id}
                request_bodies.append(request_body)
                created = self.api_client.create_post(body=request_body)
                created_posts.append(created)
                if len(created_posts) < len(planned_posts):
                    planned_posts[len(created_posts)] = XThreadPost(
                        text=planned_posts[len(created_posts)].text,
                        reply_to_post_id=created["id"],
                    )
        except PublishTargetError as exc:
            if created_posts:
                raise PublishTargetError(
                    str(exc),
                    category="reconciliation_required",
                    retryable=False,
                    requires_reconciliation=True,
                    retry_blocked=True,
                    rate_limited=exc.rate_limited,
                    retry_after_seconds=exc.retry_after_seconds,
                    status_code=exc.status_code,
                    external_id=created_posts[0]["id"],
                    response_payload={
                        **exc.response_payload,
                        "partial_post_ids": [post["id"] for post in created_posts],
                        "partial_response_bodies": [post["response_body"] for post in created_posts],
                        "request_bodies": request_bodies,
                    },
                ) from exc
            raise

        published_at = datetime.now(UTC)
        return PublishResponse(
            external_id=created_posts[0]["id"],
            published_at=published_at,
            response_payload={
                "target": self.name,
                "published_at": published_at.isoformat(),
                "root_post_id": created_posts[0]["id"],
                "post_ids": [post["id"] for post in created_posts],
                "reply_to_post_id": initial_reply_target,
                "segment_count": len(created_posts),
                "request_bodies": request_bodies,
                "response_bodies": [post["response_body"] for post in created_posts],
                "rate_limits": [post["rate_limit"] for post in created_posts],
            },
        )


def build_x_thread_plan(request: PublishRequest) -> list[XThreadPost]:
    sections = _build_sections(request)
    posts = _pack_sections(sections)
    reply_to_post_id = _extract_initial_reply_to_post_id(request)
    return [
        XThreadPost(text=post, reply_to_post_id=reply_to_post_id if index == 0 else None)
        for index, post in enumerate(posts)
    ]


def _build_sections(request: PublishRequest) -> list[str]:
    metadata = request.content.metadata
    replay_context = request.payload_snapshot.get("replay_context", {})
    if request.event_type == "UPDATE":
        material_changes = list(metadata.get("material_changes") or [])
        baseline_evidence = metadata.get("baseline_evidence") or {}
        current_evidence = metadata.get("current_evidence") or {}
        sections = [
            request.content.title,
            f"Summary: {request.content.summary}",
            f"Severity: {metadata.get('severity') or 'UNKNOWN'}",
            f"Product: {metadata.get('canonical_name') or 'unknown-product'}",
            f"Scope: {metadata.get('product_scope') or 'unknown'}",
        ]
        for change in material_changes:
            sections.append(
                "Change: "
                + f"{_humanize_change_field(change.get('field'))} "
                + f"{change.get('before', 'unknown')} -> {change.get('after', 'unknown')}"
            )
        sections.extend(
            (
                f"Baseline: {_format_signal_summary(baseline_evidence)}",
                f"Current: {_format_signal_summary(current_evidence)}",
                "Reasons: "
                + ", ".join(str(reason) for reason in metadata.get("reason_codes") or ())
                if metadata.get("reason_codes")
                else "Reasons: none",
            )
        )
        return sections

    description = ((replay_context.get("cve") or {}).get("description")) or "No description provided."
    return [
        request.content.title,
        f"Summary: {request.content.summary}",
        f"Severity: {metadata.get('severity') or 'UNKNOWN'}",
        f"Product: {metadata.get('canonical_name') or 'unknown-product'}",
        f"Scope: {metadata.get('product_scope') or 'unknown'}",
        f"Evidence: PoC={metadata.get('poc_status') or 'UNKNOWN'} ITW={metadata.get('itw_status') or 'UNKNOWN'}",
        "Reasons: "
        + ", ".join(str(reason) for reason in metadata.get("policy_reason_codes") or ())
        if metadata.get("policy_reason_codes")
        else "Reasons: none",
        f"Description: {description}",
    ]


def _extract_initial_reply_to_post_id(request: PublishRequest) -> str | None:
    if request.event_type != "UPDATE":
        return None
    replay_context = request.payload_snapshot.get("replay_context", {})
    baseline_publication = replay_context.get("baseline_publication") or {}
    external_id = baseline_publication.get("external_id")
    if isinstance(external_id, str) and external_id:
        return external_id
    raise PublishTargetError(
        "X update publish requires a baseline X post id for reply threading",
        category="reconciliation_required",
        retryable=False,
        requires_reconciliation=True,
        retry_blocked=True,
        response_payload={
            "reason": "baseline_remote_id_missing",
            "baseline_publication_event_id": baseline_publication.get("id"),
            "baseline_destination": baseline_publication.get("destination"),
        },
    )


def _pack_sections(sections: list[str]) -> list[str]:
    limit = X_MAX_WEIGHTED_LENGTH - _X_POST_INDEX_RESERVE
    flattened_sections: list[str] = []
    for section in sections:
        normalized = _normalize_section(section)
        if not normalized:
            continue
        flattened_sections.extend(_split_section(normalized, limit))
    if not flattened_sections:
        return ["CVE publication payload was empty"]

    posts: list[str] = []
    current = ""
    for section in flattened_sections:
        candidate = section if not current else f"{current}\n{section}"
        if _weighted_length(candidate) <= limit:
            current = candidate
            continue
        if current:
            posts.append(current)
        current = section
    if current:
        posts.append(current)

    if len(posts) > X_MAX_THREAD_POSTS:
        posts = posts[: X_MAX_THREAD_POSTS - 1] + [
            _truncate_to_fit("\n".join(posts[X_MAX_THREAD_POSTS - 1 :]), limit, trailer=" [truncated]")
        ]

    if len(posts) == 1:
        return [_truncate_to_fit(posts[0], X_MAX_WEIGHTED_LENGTH)]

    numbered_posts: list[str] = []
    total = len(posts)
    for index, post in enumerate(posts, start=1):
        suffix = f"\n\n{index}/{total}"
        numbered_posts.append(_truncate_to_fit(post, X_MAX_WEIGHTED_LENGTH - _weighted_length(suffix)) + suffix)
    return numbered_posts


def _split_section(text: str, limit: int) -> list[str]:
    words = text.split(" ")
    chunks: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if _weighted_length(candidate) <= limit:
            current = candidate
            continue
        if current:
            chunks.append(current)
        if _weighted_length(word) <= limit:
            current = word
            continue
        chunks.extend(_split_long_token(word, limit))
        current = ""
    if current:
        chunks.append(current)
    return chunks


def _split_long_token(token: str, limit: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for character in token:
        candidate = current + character
        if _weighted_length(candidate) <= limit:
            current = candidate
            continue
        if current:
            chunks.append(current)
        current = character
    if current:
        chunks.append(current)
    return chunks


def _truncate_to_fit(text: str, limit: int, *, trailer: str = "") -> str:
    if _weighted_length(text) <= limit:
        return text
    truncated = ""
    for character in text:
        candidate = truncated + character
        if _weighted_length(candidate + trailer) > limit:
            break
        truncated = candidate
    return (truncated.rstrip() + trailer).rstrip()


def _normalize_section(text: str) -> str:
    return " ".join(str(text).split())


def _weighted_length(text: str) -> int:
    total = 0
    for character in text:
        total += 1 if ord(character) <= 0x7F else 2
    return total


def _format_signal_summary(payload: dict[str, Any]) -> str:
    poc = payload.get("poc") or {}
    itw = payload.get("itw") or {}
    return (
        f"PoC={poc.get('status', 'UNKNOWN')} ({_format_confidence(poc.get('confidence'))}) "
        f"ITW={itw.get('status', 'UNKNOWN')} ({_format_confidence(itw.get('confidence'))})"
    )


def _format_confidence(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, (int, float)):
        return f"{float(value):.2f}"
    return str(value)


def _humanize_change_field(field_name: Any) -> str:
    if field_name == "evidence.poc_status":
        return "PoC"
    if field_name == "evidence.itw_status":
        return "ITW"
    return str(field_name or "unknown")


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except json.JSONDecodeError:
        return {"raw_text": response.text}
    if isinstance(payload, dict):
        return payload
    return {"raw_body": payload}


def _extract_rate_limit_details(response: httpx.Response) -> dict[str, Any]:
    retry_after_seconds: int | None = None
    retry_after = response.headers.get("retry-after")
    if retry_after and retry_after.isdigit():
        retry_after_seconds = int(retry_after)
    reset_at = response.headers.get("x-rate-limit-reset")
    if retry_after_seconds is None and reset_at and reset_at.isdigit():
        retry_after_seconds = max(int(reset_at) - int(time.time()), 0)
    return {
        "limit": response.headers.get("x-rate-limit-limit"),
        "remaining": response.headers.get("x-rate-limit-remaining"),
        "reset": reset_at,
        "retry_after_seconds": retry_after_seconds,
    }


def _build_signature_base_string(method: str, url: str, oauth_params: dict[str, str]) -> str:
    parameter_string = "&".join(
        f"{_percent_encode(key)}={_percent_encode(value)}"
        for key, value in sorted(oauth_params.items())
    )
    return "&".join(
        (
            method.upper(),
            _percent_encode(url),
            _percent_encode(parameter_string),
        )
    )


def _percent_encode(value: str) -> str:
    return quote(value, safe="~-._")
