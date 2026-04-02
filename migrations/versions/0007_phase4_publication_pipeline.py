"""phase 4 publication pipeline foundation

Revision ID: 0007_phase4_publication
Revises: 0006_phase3_workflow_idem
Create Date: 2026-04-02 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007_phase4_publication"
down_revision = "0006_phase3_workflow_idem"
branch_labels = None
depends_on = None

publication_event_status = postgresql.ENUM(
    "PENDING",
    "PUBLISHED",
    "FAILED",
    name="publication_event_status",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    publication_event_status.create(bind, checkfirst=True)

    op.add_column(
        "publication_events",
        sa.Column(
            "status",
            publication_event_status,
            server_default="PENDING",
            nullable=False,
        ),
    )
    op.add_column(
        "publication_events",
        sa.Column(
            "idempotency_key",
            sa.String(length=128),
            server_default="",
            nullable=False,
        ),
    )
    op.add_column("publication_events", sa.Column("external_id", sa.String(length=255), nullable=True))
    op.add_column(
        "publication_events",
        sa.Column(
            "target_response",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "publication_events",
        sa.Column(
            "attempt_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column("publication_events", sa.Column("last_attempted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("publication_events", sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("publication_events", sa.Column("last_error", sa.Text(), nullable=True))

    op.create_index(
        "ix_publication_events_idempotency_key",
        "publication_events",
        ["idempotency_key"],
        unique=False,
    )
    op.create_unique_constraint(
        "uq_publication_events_idempotency_key",
        "publication_events",
        ["idempotency_key"],
    )

    op.alter_column("publication_events", "status", server_default=None)
    op.alter_column("publication_events", "idempotency_key", server_default=None)
    op.alter_column("publication_events", "target_response", server_default=None)
    op.alter_column("publication_events", "attempt_count", server_default=None)


def downgrade() -> None:
    op.drop_constraint("uq_publication_events_idempotency_key", "publication_events", type_="unique")
    op.drop_index("ix_publication_events_idempotency_key", table_name="publication_events")

    op.drop_column("publication_events", "last_error")
    op.drop_column("publication_events", "published_at")
    op.drop_column("publication_events", "last_attempted_at")
    op.drop_column("publication_events", "attempt_count")
    op.drop_column("publication_events", "target_response")
    op.drop_column("publication_events", "external_id")
    op.drop_column("publication_events", "idempotency_key")
    op.drop_column("publication_events", "status")

    bind = op.get_bind()
    publication_event_status.drop(bind, checkfirst=True)
