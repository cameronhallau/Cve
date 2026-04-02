"""phase 5 update candidates

Revision ID: 0009_phase5_update_candidates
Revises: 0008_phase4_policy_durability
Create Date: 2026-04-02 12:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0009_phase5_update_candidates"
down_revision = "0008_phase4_policy_durability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "update_candidates",
        sa.Column("cve_id", sa.UUID(), nullable=False),
        sa.Column("publication_event_id", sa.UUID(), nullable=True),
        sa.Column("comparison_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("comparator_version", sa.String(length=64), nullable=False),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "comparison_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["publication_event_id"], ["publication_events.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "cve_id",
            "comparison_fingerprint",
            name="uq_update_candidates_cve_comparison_fingerprint",
        ),
    )
    op.create_index(
        "ix_update_candidates_comparison_fingerprint",
        "update_candidates",
        ["comparison_fingerprint"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_update_candidates_comparison_fingerprint", table_name="update_candidates")
    op.drop_table("update_candidates")
