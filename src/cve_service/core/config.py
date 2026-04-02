from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CVE Intelligence Bot Mk2"
    environment: str = "local"
    database_url: str = "postgresql+psycopg://cve:cve@localhost:55432/cve_service"
    redis_url: str = "redis://localhost:56379/0"
    rq_queue_name: str = "cve-phase0"
    health_timeout_seconds: float = Field(default=2.0, gt=0)
    ai_provider: str = "openrouter"
    ai_model: str = "openai/gpt-5.2"
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

    model_config = SettingsConfigDict(
        env_prefix="CVE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
