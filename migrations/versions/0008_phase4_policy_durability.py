"""phase 4 policy durability and conflict capture

Revision ID: 0008_phase4_policy_durability
Revises: 0007_phase4_publication
Create Date: 2026-04-02 01:00:00
"""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_phase4_policy_durability"
down_revision = "0007_phase4_publication"
branch_labels = None
depends_on = None

POLICY_CONFIG_SCHEMA_VERSION = "phase4-policy-config.v1"
POLICY_RATIONALE_SCHEMA_VERSION = "phase4-policy-rationale.v1"
POLICY_CONFLICT_SCHEMA_VERSION = "phase4-policy-conflict-resolution.v1"


def upgrade() -> None:
    op.create_table(
        "policy_configuration_snapshots",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("config_fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "config_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("config_fingerprint", name="uq_policy_configuration_snapshots_config_fingerprint"),
    )
    op.create_index(
        "ix_policy_configuration_snapshots_config_fingerprint",
        "policy_configuration_snapshots",
        ["config_fingerprint"],
        unique=False,
    )

    op.add_column("policy_decisions", sa.Column("policy_snapshot_id", sa.UUID(), nullable=True))
    op.add_column(
        "policy_decisions",
        sa.Column(
            "rationale",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "policy_decisions",
        sa.Column(
            "conflict_resolution",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.create_index("ix_policy_decisions_policy_snapshot_id", "policy_decisions", ["policy_snapshot_id"], unique=False)
    op.create_foreign_key(
        "fk_policy_decisions_policy_snapshot_id",
        "policy_decisions",
        "policy_configuration_snapshots",
        ["policy_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.add_column("publication_events", sa.Column("policy_snapshot_id", sa.UUID(), nullable=True))
    op.create_index("ix_publication_events_policy_snapshot_id", "publication_events", ["policy_snapshot_id"], unique=False)
    op.create_foreign_key(
        "fk_publication_events_policy_snapshot_id",
        "publication_events",
        "policy_configuration_snapshots",
        ["policy_snapshot_id"],
        ["id"],
        ondelete="SET NULL",
    )

    _backfill_policy_snapshot_links()

    op.alter_column("policy_configuration_snapshots", "config_snapshot", server_default=None)
    op.alter_column("policy_decisions", "rationale", server_default=None)
    op.alter_column("policy_decisions", "conflict_resolution", server_default=None)


def downgrade() -> None:
    op.drop_constraint("fk_publication_events_policy_snapshot_id", "publication_events", type_="foreignkey")
    op.drop_index("ix_publication_events_policy_snapshot_id", table_name="publication_events")
    op.drop_column("publication_events", "policy_snapshot_id")

    op.drop_constraint("fk_policy_decisions_policy_snapshot_id", "policy_decisions", type_="foreignkey")
    op.drop_index("ix_policy_decisions_policy_snapshot_id", table_name="policy_decisions")
    op.drop_column("policy_decisions", "conflict_resolution")
    op.drop_column("policy_decisions", "rationale")
    op.drop_column("policy_decisions", "policy_snapshot_id")

    op.drop_index("ix_policy_configuration_snapshots_config_fingerprint", table_name="policy_configuration_snapshots")
    op.drop_table("policy_configuration_snapshots")


def _backfill_policy_snapshot_links() -> None:
    bind = op.get_bind()
    policy_decisions = sa.table(
        "policy_decisions",
        sa.column("id", sa.UUID()),
        sa.column("policy_snapshot_id", sa.UUID()),
        sa.column("policy_version", sa.String()),
        sa.column("decision", sa.String()),
        sa.column("reason_codes", postgresql.JSONB(astext_type=sa.Text())),
    )
    publication_events = sa.table(
        "publication_events",
        sa.column("decision_id", sa.UUID()),
        sa.column("policy_snapshot_id", sa.UUID()),
    )
    policy_snapshots = sa.table(
        "policy_configuration_snapshots",
        sa.column("id", sa.UUID()),
        sa.column("policy_version", sa.String()),
        sa.column("config_fingerprint", sa.String()),
        sa.column("config_snapshot", postgresql.JSONB(astext_type=sa.Text())),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )

    versions = bind.execute(
        sa.select(policy_decisions.c.policy_version).distinct().where(policy_decisions.c.policy_version.is_not(None))
    ).scalars()
    snapshot_ids_by_version: dict[str, object] = {}
    now = datetime.now(UTC)

    for policy_version in versions:
        config_snapshot = _legacy_policy_config_snapshot(policy_version)
        config_fingerprint = _fingerprint_payload(config_snapshot)
        snapshot_id = bind.execute(
            sa.select(policy_snapshots.c.id).where(policy_snapshots.c.config_fingerprint == config_fingerprint)
        ).scalar_one_or_none()
        if snapshot_id is None:
            snapshot_id = uuid4()
            bind.execute(
                sa.insert(policy_snapshots).values(
                    id=snapshot_id,
                    policy_version=policy_version,
                    config_fingerprint=config_fingerprint,
                    config_snapshot=config_snapshot,
                    created_at=now,
                )
            )
        snapshot_ids_by_version[policy_version] = snapshot_id
        bind.execute(
            sa.update(policy_decisions)
            .where(
                policy_decisions.c.policy_version == policy_version,
                policy_decisions.c.policy_snapshot_id.is_(None),
            )
            .values(policy_snapshot_id=snapshot_id)
        )

    rows = bind.execute(
        sa.select(
            policy_decisions.c.id,
            policy_decisions.c.policy_version,
            policy_decisions.c.decision,
            policy_decisions.c.reason_codes,
            policy_decisions.c.policy_snapshot_id,
        )
    ).mappings()

    for row in rows:
        reason_codes = list(row["reason_codes"] or [])
        bind.execute(
            sa.update(policy_decisions)
            .where(policy_decisions.c.id == row["id"])
            .values(
                rationale={
                    "schema_version": POLICY_RATIONALE_SCHEMA_VERSION,
                    "outcome": row["decision"],
                    "summary": "Backfilled legacy policy decision from pre-durability data.",
                    "reason_codes": reason_codes,
                    "policy_version": row["policy_version"],
                    "backfilled": True,
                },
                conflict_resolution={
                    "schema_version": POLICY_CONFLICT_SCHEMA_VERSION,
                    "has_conflict": False,
                    "selected_outcome": row["decision"],
                    "selected_reason_codes": reason_codes,
                    "resolution_basis": "legacy_backfill",
                    "conflicts": [],
                    "policy_version": row["policy_version"],
                    "backfilled": True,
                },
            )
        )

    for policy_version, snapshot_id in snapshot_ids_by_version.items():
        bind.execute(
            sa.update(publication_events)
            .values(policy_snapshot_id=snapshot_id)
            .where(
                publication_events.c.policy_snapshot_id.is_(None),
                publication_events.c.decision_id.in_(
                    sa.select(policy_decisions.c.id).where(policy_decisions.c.policy_version == policy_version)
                ),
            )
        )


def _legacy_policy_config_snapshot(policy_version: str) -> dict[str, object]:
    return {
        "schema_version": POLICY_CONFIG_SCHEMA_VERSION,
        "policy_version": policy_version,
        "principles": {
            "rules_first": True,
            "ai_advisory_only": True,
            "hard_deterministic_denies_absolute": True,
        },
        "thresholds": {
            "ai_confidence_threshold": 0.75,
        },
        "publish_gates": {
            "deterministic_candidate_publish_on_itw": True,
            "deterministic_candidate_publish_on_poc": True,
            "ai_requires_exploit_evidence": True,
            "fail_closed_on_ai_conflict": True,
        },
        "ai": {
            "allowed_fields": [
                "enterprise_relevance_assessment",
                "exploit_path_assessment",
                "confidence",
            ],
        },
        "backfilled": True,
    }


def _fingerprint_payload(payload: dict[str, object]) -> str:
    import hashlib
    import json

    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()
