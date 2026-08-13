"""Environment-backed application settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ALMAFRICA_",
        extra="ignore",
    )

    app_name: str = "Almafrica User Onboarding Service"
    app_version: str = "0.1.0"
    environment: Literal["local", "test", "staging", "production"] = "local"
    debug: bool = False
    api_v1_prefix: str = Field(default="/api/v1", pattern=r"^/[^/](?:.*[^/])?$")


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance for the process lifetime."""
    return Settings()
