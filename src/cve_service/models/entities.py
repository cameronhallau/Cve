from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_service.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from cve_service.models.enums import (
    AIReviewOutcome,
    AuditActorType,
    ClassificationOutcome,
    CveState,
    EvidenceSignal,
    EvidenceSourceType,
    EvidenceStatus,
    PolicyDecisionOutcome,
    PublicationEventStatus,
    PublicationEventType,
)


class Product(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "products"

    vendor_name: Mapped[str] = mapped_column(String(255), nullable=False)
    product_name: Mapped[str] = mapped_column(String(255), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)


class CVE(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text())
    severity: Mapped[str | None] = mapped_column(String(32))
    source_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[CveState] = mapped_column(Enum(CveState, name="cve_state"), default=CveState.DISCOVERED, nullable=False)
    poc_status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus, name="evidence_status"),
        default=EvidenceStatus.UNKNOWN,
        nullable=False,
    )
    poc_confidence: Mapped[float | None] = mapped_column(Float())
    itw_status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus, name="evidence_status"),
        default=EvidenceStatus.UNKNOWN,
        nullable=False,
    )
    itw_confidence: Mapped[float | None] = mapped_column(Float())
    last_policy_outcome: Mapped[PolicyDecisionOutcome | None] = mapped_column(
        Enum(PolicyDecisionOutcome, name="policy_decision_outcome")
    )
    last_decision_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    classifications: Mapped[list["Classification"]] = relationship(back_populates="cve")
    ingestion_snapshots: Mapped[list["CVEIngestionSnapshot"]] = relationship(back_populates="cve")
    evidence_items: Mapped[list["Evidence"]] = relationship(back_populates="cve")
    ai_reviews: Mapped[list["AIReview"]] = relationship(back_populates="cve")
    policy_decisions: Mapped[list["PolicyDecision"]] = relationship(back_populates="cve")
    publication_events: Mapped[list["PublicationEvent"]] = relationship(back_populates="cve")
    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="cve")


class CVEIngestionSnapshot(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "cve_ingestion_snapshots"
    __table_args__ = (
        UniqueConstraint("cve_id", "source_name", "payload_hash", name="uq_cve_ingestion_snapshots_identity"),
        UniqueConstraint("cve_id", "snapshot_index", name="uq_cve_ingestion_snapshots_index"),
    )

    cve_id: Mapped[UUID] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    previous_snapshot_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("cve_ingestion_snapshots.id", ondelete="SET NULL")
    )
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_record_id: Mapped[str | None] = mapped_column(String(128))
    snapshot_index: Mapped[int] = mapped_column(Integer(), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    normalized_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE] = relationship(back_populates="ingestion_snapshots")
    previous_snapshot: Mapped["CVEIngestionSnapshot | None"] = relationship(remote_side="CVEIngestionSnapshot.id")


class Classification(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "classifications"

    cve_id: Mapped[UUID] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[UUID | None] = mapped_column(ForeignKey("cve_ingestion_snapshots.id", ondelete="SET NULL"))
    product_id: Mapped[UUID | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"))
    classifier_version: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[ClassificationOutcome] = mapped_column(
        Enum(ClassificationOutcome, name="classification_outcome"),
        default=ClassificationOutcome.DEFER,
        nullable=False,
    )
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float())
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE] = relationship(back_populates="classifications")
    snapshot: Mapped[CVEIngestionSnapshot | None] = relationship()
    product: Mapped[Product | None] = relationship()


class Evidence(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "evidence"

    cve_id: Mapped[UUID] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[UUID | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"))
    signal_type: Mapped[EvidenceSignal] = mapped_column(Enum(EvidenceSignal, name="evidence_signal"), nullable=False)
    source_type: Mapped[EvidenceSourceType] = mapped_column(
        Enum(EvidenceSourceType, name="evidence_source_type"),
        default=EvidenceSourceType.OTHER,
        nullable=False,
    )
    status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus, name="evidence_status"),
        default=EvidenceStatus.UNKNOWN,
        nullable=False,
    )
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024))
    evidence_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    freshness_ttl_seconds: Mapped[int] = mapped_column(Integer(), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float())
    is_authoritative: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    confidence_inputs: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE] = relationship(back_populates="evidence_items")
    product: Mapped[Product | None] = relationship()


class AIReview(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ai_reviews"

    cve_id: Mapped[UUID] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str | None] = mapped_column(String(64))
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    outcome: Mapped[AIReviewOutcome] = mapped_column(
        Enum(AIReviewOutcome, name="ai_review_outcome"),
        default=AIReviewOutcome.INVALID,
        nullable=False,
    )
    schema_valid: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    advisory_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    raw_response: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE] = relationship(back_populates="ai_reviews")


class PolicyDecision(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "policy_decisions"

    cve_id: Mapped[UUID] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    ai_review_id: Mapped[UUID | None] = mapped_column(ForeignKey("ai_reviews.id", ondelete="SET NULL"))
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[PolicyDecisionOutcome] = mapped_column(
        Enum(PolicyDecisionOutcome, name="policy_decision_outcome"),
        nullable=False,
    )
    deterministic_outcome: Mapped[ClassificationOutcome | None] = mapped_column(
        Enum(ClassificationOutcome, name="classification_outcome")
    )
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    inputs_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE] = relationship(back_populates="policy_decisions")
    ai_review: Mapped[AIReview | None] = relationship()


class PublicationEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "publication_events"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_publication_events_idempotency_key"),)

    cve_id: Mapped[UUID] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    decision_id: Mapped[UUID | None] = mapped_column(ForeignKey("policy_decisions.id", ondelete="SET NULL"))
    event_type: Mapped[PublicationEventType] = mapped_column(
        Enum(PublicationEventType, name="publication_event_type"),
        nullable=False,
    )
    status: Mapped[PublicationEventStatus] = mapped_column(
        Enum(PublicationEventStatus, name="publication_event_status"),
        default=PublicationEventStatus.PENDING,
        nullable=False,
    )
    destination: Mapped[str | None] = mapped_column(String(255))
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    content_hash: Mapped[str | None] = mapped_column(String(128))
    external_id: Mapped[str | None] = mapped_column(String(255))
    target_response: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text())
    payload_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE] = relationship(back_populates="publication_events")
    decision: Mapped[PolicyDecision | None] = relationship()


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "audit_events"

    cve_id: Mapped[UUID | None] = mapped_column(ForeignKey("cves.id", ondelete="SET NULL"))
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[UUID | None] = mapped_column()
    actor_type: Mapped[AuditActorType] = mapped_column(
        Enum(AuditActorType, name="audit_actor_type"),
        default=AuditActorType.SYSTEM,
        nullable=False,
    )
    actor_id: Mapped[str | None] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    state_before: Mapped[CveState | None] = mapped_column(Enum(CveState, name="cve_state"))
    state_after: Mapped[CveState | None] = mapped_column(Enum(CveState, name="cve_state"))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    cve: Mapped[CVE | None] = relationship(back_populates="audit_events")
