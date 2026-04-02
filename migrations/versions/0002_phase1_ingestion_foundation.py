"""phase 1 ingestion foundation

Revision ID: 0002_phase1_ingestion_foundation
Revises: 0001_phase0_foundation
Create Date: 2026-04-02 00:30:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_phase1_ingestion_foundation"
down_revision = "0001_phase0_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_ingestion_snapshots",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.UUID(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("source_record_id", sa.String(length=128), nullable=True),
        sa.Column("snapshot_index", sa.Integer(), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "raw_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "normalized_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("cve_id", "source_name", "payload_hash", name="uq_cve_ingestion_snapshots_identity"),
        sa.UniqueConstraint("cve_id", "snapshot_index", name="uq_cve_ingestion_snapshots_index"),
    )
    op.create_index("ix_cve_ingestion_snapshots_cve_id", "cve_ingestion_snapshots", ["cve_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cve_ingestion_snapshots_cve_id", table_name="cve_ingestion_snapshots")
    op.drop_table("cve_ingestion_snapshots")
