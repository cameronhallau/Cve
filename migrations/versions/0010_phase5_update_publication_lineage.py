"""phase 5 update publication lineage

Revision ID: 0010_phase5_update_pub_link
Revises: 0009_phase5_update_candidates
Create Date: 2026-04-02 14:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0010_phase5_update_pub_link"
down_revision = "0009_phase5_update_candidates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("publication_events", sa.Column("triggering_update_candidate_id", sa.UUID(), nullable=True))
    op.add_column("publication_events", sa.Column("baseline_publication_event_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_publication_events_triggering_update_candidate_id",
        "publication_events",
        "update_candidates",
        ["triggering_update_candidate_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_publication_events_baseline_publication_event_id",
        "publication_events",
        "publication_events",
        ["baseline_publication_event_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_publication_events_triggering_update_candidate_id",
        "publication_events",
        ["triggering_update_candidate_id"],
        unique=False,
    )
    op.create_index(
        "ix_publication_events_baseline_publication_event_id",
        "publication_events",
        ["baseline_publication_event_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_publication_events_baseline_publication_event_id", table_name="publication_events")
    op.drop_index("ix_publication_events_triggering_update_candidate_id", table_name="publication_events")
    op.drop_constraint(
        "fk_publication_events_baseline_publication_event_id",
        "publication_events",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_publication_events_triggering_update_candidate_id",
        "publication_events",
        type_="foreignkey",
    )
    op.drop_column("publication_events", "baseline_publication_event_id")
    op.drop_column("publication_events", "triggering_update_candidate_id")
