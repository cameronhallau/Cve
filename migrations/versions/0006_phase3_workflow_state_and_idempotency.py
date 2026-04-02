"""phase 3 workflow state and idempotency

Revision ID: 0006_phase3_workflow_idem
Revises: 0005_phase2_evidence_metadata
Create Date: 2026-04-02 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006_phase3_workflow_idem"
down_revision = "0005_phase2_evidence_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE cve_state ADD VALUE IF NOT EXISTS 'DEFERRED'")

    op.add_column(
        "ai_reviews",
        sa.Column(
            "request_fingerprint",
            sa.String(length=64),
            server_default="",
            nullable=False,
        ),
    )
    op.add_column(
        "ai_reviews",
        sa.Column(
            "request_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.create_index("ix_ai_reviews_request_fingerprint", "ai_reviews", ["request_fingerprint"], unique=False)

    op.add_column(
        "policy_decisions",
        sa.Column(
            "input_fingerprint",
            sa.String(length=64),
            server_default="",
            nullable=False,
        ),
    )
    op.create_index("ix_policy_decisions_input_fingerprint", "policy_decisions", ["input_fingerprint"], unique=False)

    op.alter_column("ai_reviews", "request_fingerprint", server_default=None)
    op.alter_column("policy_decisions", "input_fingerprint", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_policy_decisions_input_fingerprint", table_name="policy_decisions")
    op.drop_column("policy_decisions", "input_fingerprint")

    op.drop_index("ix_ai_reviews_request_fingerprint", table_name="ai_reviews")
    op.drop_column("ai_reviews", "request_payload")
    op.drop_column("ai_reviews", "request_fingerprint")
