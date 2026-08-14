"""Focused tests for idempotent refresh-session logout."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.core.database import get_database_session
from app.core.security import hash_refresh_token
from app.main import app
from app.models.refresh_token import RefreshToken

RAW_REFRESH_TOKEN = "logout-test-refresh-token"
TEST_JWT_SECRET = "test-only-logout-jwt-secret-at-least-32-characters"


class FakeLogoutSession:
    """Persist mutations on one in-memory refresh-session model."""

    def __init__(self, refresh_session: RefreshToken | None) -> None:
        self.refresh_session = refresh_session
        self.commit_count = 0
        self.rollback_called = False

    def scalar(self, _statement):
        return self.refresh_session

    def commit(self) -> None:
        self.commit_count += 1

    def rollback(self) -> None:
        self.rollback_called = True


def build_refresh_session() -> RefreshToken:
    return RefreshToken(
        user_id=uuid4(),
        token_hash=hash_refresh_token(RAW_REFRESH_TOKEN),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )


@pytest.fixture
def logout_client():
    def make_client(
        refresh_session: RefreshToken | None,
    ) -> tuple[TestClient, FakeLogoutSession]:
        session = FakeLogoutSession(refresh_session)
        settings = Settings(jwt_secret=SecretStr(TEST_JWT_SECRET))
        app.dependency_overrides[get_database_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: settings
        return TestClient(app), session

    yield make_client
    app.dependency_overrides.clear()


def test_logout_revokes_session_and_blocks_refresh(logout_client) -> None:
    refresh_session = build_refresh_session()
    client, session = logout_client(refresh_session)

    with client:
        logout_response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )
        refresh_response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )

    assert logout_response.status_code == 200
    assert logout_response.json() == {"message": "Logged out successfully."}
    assert refresh_session.revoked_at is not None
    assert session.commit_count == 1
    assert refresh_response.status_code == 401
    assert refresh_response.json()["detail"]["code"] == "refresh_token_revoked"


def test_repeated_logout_is_idempotent(logout_client) -> None:
    refresh_session = build_refresh_session()
    client, session = logout_client(refresh_session)

    with client:
        first_response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )
        first_revoked_at = refresh_session.revoked_at
        second_response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert refresh_session.revoked_at == first_revoked_at
    assert session.commit_count == 2


def test_unknown_refresh_token_logout_is_successful(logout_client) -> None:
    client, session = logout_client(None)

    with client:
        response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": "unknown-refresh-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out successfully."}
    assert session.commit_count == 1
