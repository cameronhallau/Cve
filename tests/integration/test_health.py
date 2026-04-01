from __future__ import annotations

from alembic import command
from fastapi.testclient import TestClient

from cve_service.main import create_app


def test_ready_endpoint_reports_db_and_queue_connectivity(alembic_config, phase0_settings) -> None:
    command.upgrade(alembic_config, "head")

    with TestClient(create_app(phase0_settings)) as client:
        response = client.get("/health/ready")

    body = response.json()

    assert response.status_code == 200
    assert body["status"] == "ok"
    assert body["checks"]["database"]["ok"] is True
    assert body["checks"]["queue"]["ok"] is True

