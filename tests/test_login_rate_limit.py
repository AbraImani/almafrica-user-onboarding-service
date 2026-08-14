"""Focused tests for process-local login brute-force protection."""

from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api.dependencies import get_login_rate_limiter
from app.core.config import Settings, get_settings
from app.core.database import get_database_session
from app.core.rate_limit import InMemoryRateLimiter
from app.main import app


class UnknownUserSession:
    """Count database lookups while behaving like an unknown account."""

    def __init__(self) -> None:
        self.query_count = 0

    def scalar(self, _statement):
        self.query_count += 1
        return None


def test_sixth_login_attempt_within_minute_is_rejected() -> None:
    session = UnknownUserSession()
    limiter = InMemoryRateLimiter(limit=5, window_seconds=60)
    settings = Settings(
        jwt_secret=SecretStr("test-rate-limit-jwt-secret-at-least-32-characters")
    )
    app.dependency_overrides[get_database_session] = lambda: session
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_login_rate_limiter] = lambda: limiter

    try:
        with TestClient(app) as client:
            responses = [
                client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "unknown@example.com",
                        "password": "wrong-password-123",
                    },
                )
                for _ in range(6)
            ]
    finally:
        app.dependency_overrides.clear()

    assert [response.status_code for response in responses[:5]] == [401] * 5
    assert responses[5].status_code == 429
    assert responses[5].json()["detail"]["code"] == "login_rate_limit_exceeded"
    assert int(responses[5].headers["Retry-After"]) >= 1
    assert session.query_count == 5


def test_rate_limit_is_per_client_and_resets_after_window() -> None:
    limiter = InMemoryRateLimiter(limit=2, window_seconds=60)

    assert limiter.check("192.0.2.1", now=0).allowed is True
    assert limiter.check("192.0.2.1", now=1).allowed is True
    denied = limiter.check("192.0.2.1", now=2)
    assert denied.allowed is False
    assert denied.retry_after_seconds == 58

    assert limiter.check("198.51.100.2", now=2).allowed is True
    assert limiter.check("192.0.2.1", now=60).allowed is True
