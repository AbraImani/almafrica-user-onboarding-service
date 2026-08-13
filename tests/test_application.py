"""Application-level smoke tests."""

from app.core.config import Settings
from app.main import app


def test_application_metadata() -> None:
    assert app.title == "Almafrica User Onboarding Service"
    assert app.version == "0.1.0"
    assert app.docs_url == "/docs"
    assert app.openapi_url == "/openapi.json"


def test_versioned_health_route_is_in_openapi_schema() -> None:
    schema = app.openapi()

    assert "/api/v1/health" in schema["paths"]


def test_settings_have_safe_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.environment == "local"
    assert settings.debug is False
    assert settings.api_v1_prefix == "/api/v1"
