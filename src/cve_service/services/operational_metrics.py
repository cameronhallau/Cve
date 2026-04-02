from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import OperationalMetric


def increment_operational_metric(
    session: Session,
    metric_key: str,
    *,
    dimensions: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
    count: int = 1,
    details: dict[str, Any] | None = None,
) -> OperationalMetric:
    if count <= 0:
        raise ValueError("count must be positive")

    normalized_dimensions = _normalize_mapping(dimensions or {})
    normalized_details = _normalize_mapping(details or {})
    dimension_key = _fingerprint_mapping(normalized_dimensions)
    effective_observed_at = _normalize_datetime(observed_at) or datetime.now(UTC)
    metric = session.scalar(
        select(OperationalMetric)
        .where(
            OperationalMetric.metric_key == metric_key,
            OperationalMetric.dimension_key == dimension_key,
        )
        .limit(1)
    )
    if metric is None:
        metric = OperationalMetric(
            metric_key=metric_key,
            dimension_key=dimension_key,
            dimensions=normalized_dimensions,
            total_count=count,
            first_observed_at=effective_observed_at,
            last_observed_at=effective_observed_at,
            last_details=normalized_details,
        )
        session.add(metric)
    else:
        metric.total_count += count
        metric.last_observed_at = effective_observed_at
        metric.last_details = normalized_details
    session.flush()
    return metric


def _fingerprint_mapping(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize_mapping(value: dict[str, Any]) -> dict[str, Any]:
    return {key: _normalize_value(value[key]) for key in sorted(value)}


def _normalize_sequence(value: list[Any] | tuple[Any, ...]) -> list[Any]:
    return [_normalize_value(item) for item in value]


def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _normalize_mapping(value)
    if isinstance(value, (list, tuple)):
        return _normalize_sequence(value)
    if isinstance(value, datetime):
        normalized = _normalize_datetime(value)
        return normalized.isoformat() if normalized is not None else None
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
