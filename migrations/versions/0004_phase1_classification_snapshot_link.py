"""phase 1 classification snapshot link

Revision ID: 0004_phase1_class_link
Revises: 0003_phase1_snapshot_lineage
Create Date: 2026-04-02 12:05:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004_phase1_class_link"
down_revision = "0003_phase1_snapshot_lineage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("classifications", sa.Column("snapshot_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_classifications_snapshot_id",
        "classifications",
        "cve_ingestion_snapshots",
        ["snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_classifications_snapshot_id", "classifications", type_="foreignkey")
    op.drop_column("classifications", "snapshot_id")
