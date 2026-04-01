"""phase 0 foundation schema

Revision ID: 0001_phase0_foundation
Revises:
Create Date: 2026-04-02 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_phase0_foundation"
down_revision = None
branch_labels = None
depends_on = None

cve_state = postgresql.ENUM(
    "DISCOVERED",
    "CLASSIFIED",
    "ENRICHMENT_PENDING",
    "AI_REVIEW_PENDING",
    "POLICY_PENDING",
    "PUBLISH_PENDING",
    "PUBLISHED",
    "UPDATE_PENDING",
    "SUPPRESSED",
    "ERROR",
    name="cve_state",
    create_type=False,
)
evidence_signal = postgresql.ENUM("POC", "ITW", "OTHER", name="evidence_signal", create_type=False)
evidence_status = postgresql.ENUM("UNKNOWN", "ABSENT", "PRESENT", name="evidence_status", create_type=False)
classification_outcome = postgresql.ENUM(
    "CANDIDATE",
    "DENY",
    "NEEDS_AI",
    "DEFER",
    name="classification_outcome",
    create_type=False,
)
ai_review_outcome = postgresql.ENUM(
    "ADVISORY_PUBLISH",
    "ADVISORY_SUPPRESS",
    "ADVISORY_DEFER",
    "INVALID",
    name="ai_review_outcome",
    create_type=False,
)
policy_decision_outcome = postgresql.ENUM(
    "PUBLISH",
    "SUPPRESS",
    "DEFER",
    name="policy_decision_outcome",
    create_type=False,
)
publication_event_type = postgresql.ENUM(
    "INITIAL",
    "UPDATE",
    "SUPPRESS",
    name="publication_event_type",
    create_type=False,
)
audit_actor_type = postgresql.ENUM("SYSTEM", "USER", "WORKER", "AI", name="audit_actor_type", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    cve_state.create(bind, checkfirst=True)
    evidence_signal.create(bind, checkfirst=True)
    evidence_status.create(bind, checkfirst=True)
    classification_outcome.create(bind, checkfirst=True)
    ai_review_outcome.create(bind, checkfirst=True)
    policy_decision_outcome.create(bind, checkfirst=True)
    publication_event_type.create(bind, checkfirst=True)
    audit_actor_type.create(bind, checkfirst=True)

    op.create_table(
        "products",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("vendor_name", sa.String(length=255), nullable=False),
        sa.Column("product_name", sa.String(length=255), nullable=False),
        sa.Column("canonical_name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("canonical_name", name="uq_products_canonical_name"),
    )

    op.create_table(
        "cves",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("source_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", cve_state, server_default="DISCOVERED", nullable=False),
        sa.Column("poc_status", evidence_status, server_default="UNKNOWN", nullable=False),
        sa.Column("poc_confidence", sa.Float(), nullable=True),
        sa.Column("itw_status", evidence_status, server_default="UNKNOWN", nullable=False),
        sa.Column("itw_confidence", sa.Float(), nullable=True),
        sa.Column("last_policy_outcome", policy_decision_outcome, nullable=True),
        sa.Column("last_decision_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("cve_id", name="uq_cves_cve_id"),
    )
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"], unique=True)

    op.create_table(
        "classifications",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", sa.UUID(), sa.ForeignKey("products.id", ondelete="SET NULL"), nullable=True),
        sa.Column("classifier_version", sa.String(length=64), nullable=True),
        sa.Column("outcome", classification_outcome, server_default="DEFER", nullable=False),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", sa.UUID(), sa.ForeignKey("products.id", ondelete="SET NULL"), nullable=True),
        sa.Column("signal_type", evidence_signal, nullable=False),
        sa.Column("status", evidence_status, server_default="UNKNOWN", nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("source_url", sa.String(length=1024), nullable=True),
        sa.Column("evidence_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("is_authoritative", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "raw_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "ai_reviews",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=True),
        sa.Column("outcome", ai_review_outcome, server_default="INVALID", nullable=False),
        sa.Column("schema_valid", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "advisory_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "raw_response",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ai_review_id", sa.UUID(), sa.ForeignKey("ai_reviews.id", ondelete="SET NULL"), nullable=True),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("decision", policy_decision_outcome, nullable=False),
        sa.Column("deterministic_outcome", classification_outcome, nullable=True),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "inputs_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "publication_events",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("decision_id", sa.UUID(), sa.ForeignKey("policy_decisions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", publication_event_type, nullable=False),
        sa.Column("destination", sa.String(length=255), nullable=True),
        sa.Column("content_hash", sa.String(length=128), nullable=True),
        sa.Column(
            "payload_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="SET NULL"), nullable=True),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.UUID(), nullable=True),
        sa.Column("actor_type", audit_actor_type, server_default="SYSTEM", nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("state_before", cve_state, nullable=True),
        sa.Column("state_after", cve_state, nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("publication_events")
    op.drop_table("policy_decisions")
    op.drop_table("ai_reviews")
    op.drop_table("evidence")
    op.drop_table("classifications")
    op.drop_index("ix_cves_cve_id", table_name="cves")
    op.drop_table("cves")
    op.drop_table("products")

    bind = op.get_bind()
    audit_actor_type.drop(bind, checkfirst=True)
    publication_event_type.drop(bind, checkfirst=True)
    policy_decision_outcome.drop(bind, checkfirst=True)
    ai_review_outcome.drop(bind, checkfirst=True)
    classification_outcome.drop(bind, checkfirst=True)
    evidence_status.drop(bind, checkfirst=True)
    evidence_signal.drop(bind, checkfirst=True)
    cve_state.drop(bind, checkfirst=True)
