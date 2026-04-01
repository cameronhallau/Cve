from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from cve_service.core.config import Settings

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_URL = "postgresql+psycopg://cve:cve@localhost:55432/cve_service"
DEFAULT_REDIS_URL = "redis://localhost:56379/0"


def _admin_database_url(database_url: str) -> str:
    url: URL = make_url(database_url)
    return url.set(database="postgres").render_as_string(hide_password=False)


@pytest.fixture(scope="session")
def redis_url() -> str:
    return os.getenv("CVE_REDIS_URL", DEFAULT_REDIS_URL)


@pytest.fixture
def temp_database_url() -> str:
    seed_url = os.getenv("CVE_DATABASE_URL", DEFAULT_DATABASE_URL)
    base_url = make_url(seed_url)
    admin_engine = create_engine(_admin_database_url(seed_url), isolation_level="AUTOCOMMIT")
    database_name = f"cve_phase0_{uuid4().hex}"

    with admin_engine.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{database_name}"'))

    test_database_url = base_url.set(database=database_name).render_as_string(hide_password=False)

    try:
        yield test_database_url
    finally:
        test_engine = create_engine(test_database_url)
        test_engine.dispose()

        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :database_name
                      AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": database_name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{database_name}"'))

        admin_engine.dispose()


@pytest.fixture
def alembic_config(temp_database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", temp_database_url)
    return config


@pytest.fixture
def phase0_settings(temp_database_url: str, redis_url: str) -> Settings:
    return Settings(
        app_name="CVE Intelligence Bot Mk2 Test",
        environment="test",
        database_url=temp_database_url,
        redis_url=redis_url,
        rq_queue_name=f"phase0-test-{uuid4().hex}",
        health_timeout_seconds=2.0,
    )
