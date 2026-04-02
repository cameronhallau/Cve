"""phase 5 operational alerts

Revision ID: 0012_phase5_operational_alerts
Revises: 0011_phase5_operational_metrics
Create Date: 2026-04-02 18:45:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0012_phase5_operational_alerts"
down_revision = "0011_phase5_operational_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operational_alert_states",
        sa.Column("alert_key", sa.String(length=160), nullable=False),
        sa.Column("rule_key", sa.String(length=128), nullable=False),
        sa.Column("scope_key", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("contract_key", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("runbook_path", sa.String(length=255), nullable=True),
        sa.Column("current_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_transition_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_key", name="uq_operational_alert_states_alert_key"),
    )
    op.create_index("ix_operational_alert_states_alert_key", "operational_alert_states", ["alert_key"], unique=False)
    op.create_index("ix_operational_alert_states_rule_key", "operational_alert_states", ["rule_key"], unique=False)
    op.create_index("ix_operational_alert_states_scope_key", "operational_alert_states", ["scope_key"], unique=False)
    op.create_index("ix_operational_alert_states_status", "operational_alert_states", ["status"], unique=False)

    op.create_table(
        "operational_alert_transitions",
        sa.Column("alert_state_id", sa.UUID(), nullable=False),
        sa.Column("alert_key", sa.String(length=160), nullable=False),
        sa.Column("rule_key", sa.String(length=128), nullable=False),
        sa.Column("transition_type", sa.String(length=32), nullable=False),
        sa.Column("status_before", sa.String(length=32), nullable=True),
        sa.Column("status_after", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["alert_state_id"], ["operational_alert_states.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_operational_alert_transitions_alert_state_id",
        "operational_alert_transitions",
        ["alert_state_id"],
        unique=False,
    )
    op.create_index("ix_operational_alert_transitions_alert_key", "operational_alert_transitions", ["alert_key"], unique=False)
    op.create_index("ix_operational_alert_transitions_rule_key", "operational_alert_transitions", ["rule_key"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_operational_alert_transitions_rule_key", table_name="operational_alert_transitions")
    op.drop_index("ix_operational_alert_transitions_alert_key", table_name="operational_alert_transitions")
    op.drop_index("ix_operational_alert_transitions_alert_state_id", table_name="operational_alert_transitions")
    op.drop_table("operational_alert_transitions")

    op.drop_index("ix_operational_alert_states_status", table_name="operational_alert_states")
    op.drop_index("ix_operational_alert_states_scope_key", table_name="operational_alert_states")
    op.drop_index("ix_operational_alert_states_rule_key", table_name="operational_alert_states")
    op.drop_index("ix_operational_alert_states_alert_key", table_name="operational_alert_states")
    op.drop_table("operational_alert_states")
