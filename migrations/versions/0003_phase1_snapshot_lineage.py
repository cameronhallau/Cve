"""phase 1 snapshot lineage

Revision ID: 0003_phase1_snapshot_lineage
Revises: 0002_phase1_ingestion_foundation
Create Date: 2026-04-02 11:15:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003_phase1_snapshot_lineage"
down_revision = "0002_phase1_ingestion_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cve_ingestion_snapshots", sa.Column("previous_snapshot_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_cve_ingestion_snapshots_previous_snapshot_id",
        "cve_ingestion_snapshots",
        "cve_ingestion_snapshots",
        ["previous_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_cve_ingestion_snapshots_previous_snapshot_id",
        "cve_ingestion_snapshots",
        type_="foreignkey",
    )
    op.drop_column("cve_ingestion_snapshots", "previous_snapshot_id")
