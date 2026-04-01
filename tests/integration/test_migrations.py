from __future__ import annotations

from alembic import command
from sqlalchemy import create_engine, inspect, text

EXPECTED_TABLES = {
    "ai_reviews",
    "audit_events",
    "classifications",
    "cves",
    "evidence",
    "policy_decisions",
    "products",
    "publication_events",
}


def test_migrations_apply_and_rollback_cleanly(alembic_config, temp_database_url) -> None:
    command.upgrade(alembic_config, "head")

    upgraded_engine = create_engine(temp_database_url)
    try:
        upgraded_tables = set(inspect(upgraded_engine).get_table_names())
    finally:
        upgraded_engine.dispose()

    assert EXPECTED_TABLES.issubset(upgraded_tables)
    assert "alembic_version" in upgraded_tables

    command.downgrade(alembic_config, "base")

    downgraded_engine = create_engine(temp_database_url)
    try:
        downgraded_tables = set(inspect(downgraded_engine).get_table_names())
        with downgraded_engine.connect() as connection:
            version_rows = connection.execute(text("SELECT COUNT(*) FROM alembic_version")).scalar_one()
    finally:
        downgraded_engine.dispose()

    assert EXPECTED_TABLES.isdisjoint(downgraded_tables)
    assert version_rows == 0
