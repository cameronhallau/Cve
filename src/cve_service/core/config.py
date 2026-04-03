from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CVE Intelligence Bot Mk2"
    environment: str = "local"
    database_url: str = "postgresql+psycopg://cve:cve@localhost:55432/cve_service"
    redis_url: str = "redis://localhost:56379/0"
    rq_queue_name: str = "cve-phase0"
    health_timeout_seconds: float = Field(default=2.0, gt=0)
    external_enrichment_enabled: bool = False
    external_enrichment_timeout_seconds: float = Field(default=10.0, gt=0)
    external_enrichment_cache_ttl_seconds: int = Field(default=3600, gt=0)
    external_enrichment_max_matches: int = Field(default=5, gt=0, le=25)
    ai_provider: str = "openrouter"
    ai_model: str = "deepseek/deepseek-v3.2"
    ai_timeout_seconds: float = Field(default=30.0, gt=0)
    ai_max_completion_tokens: int = Field(default=400, gt=0)
    ai_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CVE_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"),
    )
    openrouter_http_referer: str | None = None
    openrouter_title: str | None = None
    vulncheck_kev_url: str = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
    vulncheck_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CVE_VULNCHECK_API_KEY", "VULNCHECK_API_KEY"),
    )
    epss_url: str = "https://api.first.org/data/v1/epss"
    github_poc_enabled: bool = False
    github_api_base_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    github_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CVE_GITHUB_TOKEN", "GITHUB_TOKEN"),
    )
    searchsploit_binary_path: str = "searchsploit"
    exploitdb_search_url: str = "https://www.exploit-db.com/search"
    publish_target_name: str = "console"
    cve_org_delta_log_url: str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
    cve_org_http_timeout_seconds: float = Field(default=20.0, gt=0)
    x_api_base_url: str = "https://api.x.com"
    x_timeout_seconds: float = Field(default=15.0, gt=0)
    x_auth_mode: Literal["oauth1_user", "oauth2_bearer"] | None = None
    x_consumer_key: str | None = None
    x_consumer_secret: str | None = None
    x_access_token: str | None = None
    x_access_token_secret: str | None = None
    x_bearer_token: str | None = None

    model_config = SettingsConfigDict(
        env_prefix="CVE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_publish_target_settings(self) -> Settings:
        if not self.cve_org_delta_log_url.strip():
            raise ValueError("CVE_CVE_ORG_DELTA_LOG_URL must not be empty")

        if self.publish_target_name.strip().lower() != "x":
            return self

        if self.x_auth_mode is None:
            raise ValueError("CVE publish target 'x' requires CVE_X_AUTH_MODE")

        if self.x_auth_mode == "oauth1_user":
            missing = [
                field_name
                for field_name, value in (
                    ("CVE_X_CONSUMER_KEY", self.x_consumer_key),
                    ("CVE_X_CONSUMER_SECRET", self.x_consumer_secret),
                    ("CVE_X_ACCESS_TOKEN", self.x_access_token),
                    ("CVE_X_ACCESS_TOKEN_SECRET", self.x_access_token_secret),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "CVE publish target 'x' with oauth1_user auth requires "
                    + ", ".join(missing)
                )
            return self

        if self.x_auth_mode == "oauth2_bearer" and not self.x_bearer_token:
            raise ValueError("CVE publish target 'x' with oauth2_bearer auth requires CVE_X_BEARER_TOKEN")

        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
