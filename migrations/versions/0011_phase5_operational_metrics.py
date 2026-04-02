"""phase 5 operational metrics

Revision ID: 0011_phase5_operational_metrics
Revises: 0010_phase5_update_pub_link
Create Date: 2026-04-02 16:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0011_phase5_operational_metrics"
down_revision = "0010_phase5_update_pub_link"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operational_metrics",
        sa.Column("metric_key", sa.String(length=128), nullable=False),
        sa.Column("dimension_key", sa.String(length=64), nullable=False),
        sa.Column("dimensions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("total_count", sa.Integer(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "metric_key",
            "dimension_key",
            name="uq_operational_metrics_metric_dimension",
        ),
    )
    op.create_index("ix_operational_metrics_dimension_key", "operational_metrics", ["dimension_key"], unique=False)
    op.create_index("ix_operational_metrics_metric_key", "operational_metrics", ["metric_key"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_operational_metrics_metric_key", table_name="operational_metrics")
    op.drop_index("ix_operational_metrics_dimension_key", table_name="operational_metrics")
    op.drop_table("operational_metrics")
