from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from cve_service.models.entities import AuditEvent, CVE, CVEIngestionSnapshot, Classification, Product
from cve_service.models.enums import AuditActorType, CveState
from cve_service.services.classifier import CLASSIFIER_VERSION, classify_record, canonicalize_product
from cve_service.services.reason_codes import REASON_CODE_REGISTRY_VERSION, reason_code_registry_snapshot
from cve_service.services.state_machine import InvalidStateTransition, guard_transition


class PublicFeedRecord(BaseModel):
    source_name: str = "public-fixture-feed"
    source_record_id: str | None = None
    cve_id: str
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    source_published_at: datetime | None = None
    source_modified_at: datetime | None = None
    vendor_name: str
    product_name: str
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def populate_source_record_id(self) -> "PublicFeedRecord":
        if self.source_record_id is None:
            self.source_record_id = self.cve_id
        return self


@dataclass(frozen=True, slots=True)
class IngestionResult:
    cve_id: str
    snapshot_created: bool
    classification_created: bool
    snapshot_index: int
    classification_id: UUID | None
    classifier_version: str | None
    reason_codes: tuple[str, ...]
    reason_code_registry_version: str
    ai_route_eligible: bool
    ai_route_allowed: bool
    state: CveState


def ingest_public_feed_record(session: Session, record: PublicFeedRecord) -> IngestionResult:
    cve = _get_or_create_cve(session, record)
    product = _get_or_create_product(session, record.vendor_name, record.product_name)
    normalized_payload = _build_normalized_payload(record, product)
    payload_hash = _hash_payload(normalized_payload)

    existing_snapshot = session.scalar(
        select(CVEIngestionSnapshot).where(
            CVEIngestionSnapshot.cve_id == cve.id,
            CVEIngestionSnapshot.source_name == record.source_name,
            CVEIngestionSnapshot.payload_hash == payload_hash,
        )
    )

    if existing_snapshot is not None:
        existing_classification = _latest_classification_for_cve(session, cve.id)
        _write_audit_event(
            session,
            cve=cve,
            entity_type="cve_ingestion_snapshot",
            entity_id=existing_snapshot.id,
            event_type="ingestion.idempotent_reuse",
            state_before=cve.state,
            state_after=cve.state,
            details={
                "source_name": existing_snapshot.source_name,
                "snapshot_index": existing_snapshot.snapshot_index,
                "payload_hash": existing_snapshot.payload_hash,
            },
        )
        if existing_classification is not None:
            _write_audit_event(
                session,
                cve=cve,
                entity_type="classification",
                entity_id=existing_classification.id,
                event_type="classification.reused",
                state_before=cve.state,
                state_after=cve.state,
                details={
                    "classifier_version": existing_classification.classifier_version,
                    "reason_codes": existing_classification.reason_codes,
                    "reason_code_registry_version": existing_classification.details.get(
                        "reason_code_registry_version",
                        REASON_CODE_REGISTRY_VERSION,
                    ),
                    "outcome": existing_classification.outcome.value,
                },
            )

        session.flush()
        return IngestionResult(
            cve_id=cve.cve_id,
            snapshot_created=False,
            classification_created=False,
            snapshot_index=existing_snapshot.snapshot_index,
            classification_id=existing_classification.id if existing_classification is not None else None,
            classifier_version=existing_classification.classifier_version if existing_classification is not None else None,
            reason_codes=tuple(existing_classification.reason_codes) if existing_classification is not None else (),
            reason_code_registry_version=existing_classification.details.get(
                "reason_code_registry_version",
                REASON_CODE_REGISTRY_VERSION,
            )
            if existing_classification is not None
            else REASON_CODE_REGISTRY_VERSION,
            ai_route_eligible=bool(
                existing_classification is not None
                and existing_classification.details.get("ai_route", {}).get("eligible", False)
            ),
            ai_route_allowed=False,
            state=cve.state,
        )

    snapshot_index = _next_snapshot_index(session, cve.id)
    snapshot = CVEIngestionSnapshot(
        cve_id=cve.id,
        source_name=record.source_name,
        source_record_id=record.source_record_id,
        snapshot_index=snapshot_index,
        payload_hash=payload_hash,
        source_modified_at=record.source_modified_at,
        raw_payload=record.raw_payload or record.model_dump(mode="json"),
        normalized_payload=normalized_payload,
    )
    session.add(snapshot)
    session.flush()

    _write_audit_event(
        session,
        cve=cve,
        entity_type="cve_ingestion_snapshot",
        entity_id=snapshot.id,
        event_type="ingestion.snapshot_created",
        state_before=cve.state,
        state_after=cve.state,
        details={
            "source_name": snapshot.source_name,
            "source_record_id": snapshot.source_record_id,
            "snapshot_index": snapshot.snapshot_index,
            "payload_hash": snapshot.payload_hash,
            "source_modified_at": _serialize_datetime(snapshot.source_modified_at),
        },
    )

    classification_result = classify_record(record.severity, canonicalize_product(record.vendor_name, record.product_name))
    classification_details = {
        **classification_result.details,
        "reason_codes": list(classification_result.reason_codes),
        "reason_code_definitions": reason_code_registry_snapshot(classification_result.reason_codes),
        "snapshot_index": snapshot.snapshot_index,
        "snapshot_id": str(snapshot.id),
    }
    classification = Classification(
        cve_id=cve.id,
        product_id=product.id,
        classifier_version=CLASSIFIER_VERSION,
        outcome=classification_result.outcome,
        reason_codes=list(classification_result.reason_codes),
        confidence=classification_result.confidence,
        details=classification_details,
    )
    session.add(classification)

    state_before = cve.state
    state_after = _resolve_state(cve.state, classification_result.next_state)
    cve.state = state_after
    session.flush()

    _write_audit_event(
        session,
        cve=cve,
        entity_type="classification",
        entity_id=classification.id,
        event_type="classification.persisted",
        state_before=state_before,
        state_after=state_after,
        details={
            "classifier_version": CLASSIFIER_VERSION,
            "reason_codes": list(classification_result.reason_codes),
            "reason_code_registry_version": REASON_CODE_REGISTRY_VERSION,
            "reason_code_definitions": reason_code_registry_snapshot(classification_result.reason_codes),
            "outcome": classification_result.outcome.value,
            "confidence": classification_result.confidence,
            "snapshot_index": snapshot.snapshot_index,
            "ai_route": classification_result.details["ai_route"],
        },
    )

    session.flush()
    return IngestionResult(
        cve_id=cve.cve_id,
        snapshot_created=True,
        classification_created=True,
        snapshot_index=snapshot.snapshot_index,
        classification_id=classification.id,
        classifier_version=classification.classifier_version,
        reason_codes=tuple(classification.reason_codes),
        reason_code_registry_version=REASON_CODE_REGISTRY_VERSION,
        ai_route_eligible=classification_result.ai_route_eligible,
        ai_route_allowed=False,
        state=cve.state,
    )


def _build_normalized_payload(record: PublicFeedRecord, product: Product) -> dict[str, Any]:
    return {
        "cve_id": record.cve_id,
        "title": record.title,
        "description": record.description,
        "severity": record.severity.upper() if record.severity is not None else None,
        "source_published_at": _serialize_datetime(record.source_published_at),
        "source_modified_at": _serialize_datetime(record.source_modified_at),
        "product": {
            "vendor_name": record.vendor_name,
            "product_name": record.product_name,
            "canonical_name": product.canonical_name,
        },
    }


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _hash_payload(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _get_or_create_cve(session: Session, record: PublicFeedRecord) -> CVE:
    statement: Select[tuple[CVE]] = select(CVE).where(CVE.cve_id == record.cve_id)
    cve = session.scalar(statement)
    if cve is None:
        cve = CVE(
            cve_id=record.cve_id,
            title=record.title,
            description=record.description,
            severity=record.severity.upper() if record.severity is not None else None,
            source_published_at=record.source_published_at,
            source_modified_at=record.source_modified_at,
            state=CveState.DISCOVERED,
        )
        session.add(cve)
        session.flush()
        return cve

    cve.title = record.title
    cve.description = record.description
    cve.severity = record.severity.upper() if record.severity is not None else None
    cve.source_published_at = record.source_published_at
    cve.source_modified_at = record.source_modified_at
    session.flush()
    return cve


def _get_or_create_product(session: Session, vendor_name: str, product_name: str) -> Product:
    canonical_product = canonicalize_product(vendor_name, product_name)
    product = session.scalar(select(Product).where(Product.canonical_name == canonical_product.canonical_name))
    if product is not None:
        return product

    product = Product(
        vendor_name=vendor_name,
        product_name=product_name,
        canonical_name=canonical_product.canonical_name,
    )
    session.add(product)
    session.flush()
    return product


def _next_snapshot_index(session: Session, cve_pk: Any) -> int:
    current_max = session.scalar(
        select(func.max(CVEIngestionSnapshot.snapshot_index)).where(CVEIngestionSnapshot.cve_id == cve_pk)
    )
    return 1 if current_max is None else int(current_max) + 1


def _latest_classification_for_cve(session: Session, cve_pk: Any) -> Classification | None:
    return session.scalar(
        select(Classification)
        .where(Classification.cve_id == cve_pk)
        .order_by(Classification.created_at.desc())
        .limit(1)
    )


def _resolve_state(current_state: CveState, desired_state: CveState) -> CveState:
    if current_state == desired_state:
        return current_state

    try:
        return guard_transition(current_state, desired_state)
    except InvalidStateTransition:
        return CveState.SUPPRESSED


def _write_audit_event(
    session: Session,
    *,
    cve: CVE,
    entity_type: str,
    entity_id: Any,
    event_type: str,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )
