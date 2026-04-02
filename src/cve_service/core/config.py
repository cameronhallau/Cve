from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CVE Intelligence Bot Mk2"
    environment: str = "local"
    database_url: str = "postgresql+psycopg://cve:cve@localhost:55432/cve_service"
    redis_url: str = "redis://localhost:56379/0"
    rq_queue_name: str = "cve-phase0"
    health_timeout_seconds: float = Field(default=2.0, gt=0)

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
