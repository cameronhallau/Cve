from __future__ import annotations

from pydantic import BaseModel


class HealthCheckStatus(BaseModel):
    ok: bool
    detail: str


class LiveResponse(BaseModel):
    status: str


class ReadyResponse(BaseModel):
    status: str
    checks: dict[str, HealthCheckStatus]

