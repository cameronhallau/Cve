from __future__ import annotations

from typing import Any


def noop_job(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"status": "processed", "payload": payload or {}}

