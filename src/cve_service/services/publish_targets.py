from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from cve_service.services.publish_content import PublishContent


class PublishTargetError(RuntimeError):
    """Raised when an external publish target rejects or fails a request."""


@dataclass(frozen=True, slots=True)
class PublishRequest:
    cve_id: str
    event_type: str
    target_name: str
    idempotency_key: str
    content_hash: str
    content: PublishContent
    payload_snapshot: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PublishResponse:
    external_id: str | None
    published_at: datetime
    response_payload: dict[str, Any]


class PublishTarget(Protocol):
    name: str

    def publish(self, request: PublishRequest) -> PublishResponse:
        """Publish the canonical content to an external destination."""


@dataclass(slots=True)
class InMemoryPublishTarget:
    name: str = "in-memory"
    failures_before_success: int = 0
    published_requests: list[PublishRequest] = field(default_factory=list)

    def publish(self, request: PublishRequest) -> PublishResponse:
        if self.failures_before_success > 0:
            self.failures_before_success -= 1
            raise PublishTargetError(f"{self.name} temporary failure")

        self.published_requests.append(request)
        published_at = datetime.now(UTC)
        return PublishResponse(
            external_id=f"{self.name}:{request.cve_id}:{len(self.published_requests)}",
            published_at=published_at,
            response_payload={
                "target": self.name,
                "published_at": published_at.isoformat(),
                "content_hash": request.content_hash,
            },
        )


@dataclass(frozen=True, slots=True)
class InlinePublishTarget:
    name: str = "inline"
    fail_with: str | None = None
    external_id: str | None = None
    response_payload: dict[str, Any] = field(default_factory=dict)

    def publish(self, request: PublishRequest) -> PublishResponse:
        if self.fail_with is not None:
            raise PublishTargetError(self.fail_with)

        published_at = datetime.now(UTC)
        return PublishResponse(
            external_id=self.external_id or f"{self.name}:{request.cve_id}",
            published_at=published_at,
            response_payload={
                "target": self.name,
                "published_at": published_at.isoformat(),
                **self.response_payload,
            },
        )


@dataclass(frozen=True, slots=True)
class ConsolePublishTarget:
    name: str = "console"

    def publish(self, request: PublishRequest) -> PublishResponse:
        published_at = datetime.now(UTC)
        return PublishResponse(
            external_id=f"{self.name}:{request.cve_id}",
            published_at=published_at,
            response_payload={
                "target": self.name,
                "published_at": published_at.isoformat(),
                "delivery_mode": "console",
            },
        )


def build_publish_target(
    *,
    target_name: str | None = None,
    behavior: dict[str, Any] | None = None,
) -> PublishTarget:
    resolved_name = target_name or "console"
    resolved_behavior = behavior or {}
    if resolved_name == "inline":
        return InlinePublishTarget(
            name=resolved_behavior.get("name", resolved_name),
            fail_with=resolved_behavior.get("fail_with"),
            external_id=resolved_behavior.get("external_id"),
            response_payload=dict(resolved_behavior.get("response_payload", {})),
        )
    return ConsolePublishTarget(name=resolved_behavior.get("name", resolved_name))
