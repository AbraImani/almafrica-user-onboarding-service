"""Environment-backed application settings."""

from functools import lru_cache
from typing import Literal

from pydantic import EmailStr, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


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
    database_host: str = "localhost"
    database_port: int = Field(default=5432, ge=1, le=65535)
    database_name: str = "almafrica"
    database_user: str = "almafrica"
    database_password: SecretStr = SecretStr("almafrica")
    database_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    smtp_host: str = "localhost"
    smtp_port: int = Field(default=1025, ge=1, le=65535)
    smtp_from_email: EmailStr = "no-reply@example.com"
    smtp_from_name: str = Field(default="Almafrica", min_length=1, max_length=100)
    smtp_timeout_seconds: int = Field(default=10, ge=1, le=60)
    email_verification_url: str = Field(
        default="http://localhost:8000/api/v1/auth/verify-email",
        pattern=r"^https?://",
    )

    @property
    def sqlalchemy_database_url(self) -> URL:
        """Build a safely escaped SQLAlchemy URL from database settings."""
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.database_user,
            password=self.database_password.get_secret_value(),
            host=self.database_host,
            port=self.database_port,
            database=self.database_name,
        )


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance for the process lifetime."""
    return Settings()
