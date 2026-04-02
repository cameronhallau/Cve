"""phase 2 evidence metadata

Revision ID: 0005_phase2_evidence_metadata
Revises: 0004_phase1_class_link
Create Date: 2026-04-02 00:30:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005_phase2_evidence_metadata"
down_revision = "0004_phase1_class_link"
branch_labels = None
depends_on = None

evidence_source_type = postgresql.ENUM(
    "OTHER",
    "VENDOR_ADVISORY",
    "TRUSTED_POC",
    "TRUSTED_ITW",
    "KEV",
    name="evidence_source_type",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    evidence_source_type.create(bind, checkfirst=True)

    op.add_column(
        "evidence",
        sa.Column("source_type", evidence_source_type, server_default="OTHER", nullable=False),
    )
    op.add_column(
        "evidence",
        sa.Column("source_record_id", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "evidence",
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "evidence",
        sa.Column("freshness_ttl_seconds", sa.Integer(), server_default="2592000", nullable=False),
    )
    op.add_column(
        "evidence",
        sa.Column(
            "confidence_inputs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )

    op.execute(
        """
        UPDATE evidence
        SET source_record_id = COALESCE(source_url, source_name, id::text),
            collected_at = COALESCE(evidence_timestamp, created_at, now())
        """
    )

    op.alter_column("evidence", "source_record_id", nullable=False)
    op.alter_column("evidence", "collected_at", nullable=False)
    op.create_index(
        "ix_evidence_identity",
        "evidence",
        ["cve_id", "signal_type", "source_type", "source_name", "source_record_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_evidence_identity", table_name="evidence")
    op.drop_column("evidence", "confidence_inputs")
    op.drop_column("evidence", "freshness_ttl_seconds")
    op.drop_column("evidence", "collected_at")
    op.drop_column("evidence", "source_record_id")
    op.drop_column("evidence", "source_type")

    bind = op.get_bind()
    evidence_source_type.drop(bind, checkfirst=True)
