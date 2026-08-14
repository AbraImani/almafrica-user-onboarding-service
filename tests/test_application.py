"""Application-level smoke tests."""

import json

from app.api import health
from app.core.config import Settings
from app.main import app


def test_application_metadata() -> None:
    assert app.title == "Almafrica User Onboarding Service"
    assert app.version == "0.1.0"
    assert app.docs_url == "/docs"
    assert app.openapi_url == "/openapi.json"


def test_health_route_is_in_openapi_schema() -> None:
    schema = app.openapi()

    assert "/health" in schema["paths"]
    assert "/api/v1/health" not in schema["paths"]


def test_health_check_reports_healthy_database(monkeypatch) -> None:
    monkeypatch.setattr(health, "database_is_reachable", lambda: True)

    response = health.health_check()

    assert response.status_code == 200
    assert json.loads(response.body) == {
        "status": "healthy",
        "dependencies": {"database": {"status": "healthy"}},
    }


def test_health_check_reports_unavailable_database(monkeypatch) -> None:
    monkeypatch.setattr(health, "database_is_reachable", lambda: False)

    response = health.health_check()

    assert response.status_code == 503
    assert json.loads(response.body) == {
        "status": "unhealthy",
        "dependencies": {"database": {"status": "unhealthy"}},
    }


def test_settings_have_safe_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.environment == "local"
    assert settings.debug is False
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.database_host == "localhost"
    assert settings.database_connect_timeout_seconds == 3
    assert settings.sqlalchemy_database_url.drivername == "postgresql+psycopg"


def test_database_url_escapes_credentials() -> None:
    settings = Settings(
        _env_file=None,
        database_user="user@example.com",
        database_password="secret/value",
    )

    assert settings.sqlalchemy_database_url.username == "user@example.com"
    assert settings.sqlalchemy_database_url.password == "secret/value"
