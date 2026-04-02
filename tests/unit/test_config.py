from __future__ import annotations

import pytest
from pydantic import ValidationError

from cve_service.core.config import Settings


def test_settings_require_x_credentials_when_x_target_is_enabled() -> None:
    with pytest.raises(ValidationError):
        Settings(publish_target_name="x")


def test_settings_accept_x_oauth1_configuration() -> None:
    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth1_user",
        x_consumer_key="consumer-key",
        x_consumer_secret="consumer-secret",
        x_access_token="access-token",
        x_access_token_secret="access-token-secret",
    )

    assert settings.publish_target_name == "x"
    assert settings.x_auth_mode == "oauth1_user"


def test_settings_accept_x_oauth2_bearer_configuration() -> None:
    settings = Settings(
        publish_target_name="x",
        x_auth_mode="oauth2_bearer",
        x_bearer_token="bearer-token",
    )

    assert settings.publish_target_name == "x"
    assert settings.x_auth_mode == "oauth2_bearer"
