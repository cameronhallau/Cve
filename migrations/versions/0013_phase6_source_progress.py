"""phase 6 source progress

Revision ID: 0013_phase6_source_progress
Revises: 0012_phase5_operational_alerts
Create Date: 2026-04-02 20:05:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0013_phase6_source_progress"
down_revision = "0012_phase5_operational_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_progress",
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("cursor", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("last_poll_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_poll_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_upstream_fetch_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_status", sa.String(length=32), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("last_run_details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_name", name="uq_source_progress_source_name"),
    )
    op.create_index("ix_source_progress_source_name", "source_progress", ["source_name"], unique=False)

    op.alter_column("source_progress", "cursor", server_default=sa.text("'{}'::jsonb"))
    op.alter_column("source_progress", "last_error", server_default=sa.text("'{}'::jsonb"))
    op.alter_column("source_progress", "last_run_details", server_default=sa.text("'{}'::jsonb"))


def downgrade() -> None:
    op.drop_index("ix_source_progress_source_name", table_name="source_progress")
    op.drop_table("source_progress")
