"""phase 7 external enrichment

Revision ID: 0014_phase7_external_enrichment
Revises: 0013_phase6_source_progress
Create Date: 2026-04-03 13:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0014_phase7_external_enrichment"
down_revision = "0013_phase6_source_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cves",
        sa.Column(
            "external_enrichment",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("cves", "external_enrichment")
