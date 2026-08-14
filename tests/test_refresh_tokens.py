"""Focused tests for persisted refresh-token sessions."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.core.database import get_database_session
from app.core.security import decode_access_token, hash_refresh_token
from app.main import app
from app.models.refresh_token import RefreshToken
from app.models.user import User, UserRole

RAW_REFRESH_TOKEN = "test-refresh-token-value"
TEST_JWT_SECRET = "test-only-refresh-jwt-secret-at-least-32-characters"


class FakeRefreshSession:
    """Return refresh-session and user rows in query order."""

    def __init__(
        self,
        refresh_session: RefreshToken | None,
        user: User | None,
    ) -> None:
        self.refresh_session = refresh_session
        self.user = user
        self.scalar_calls = 0
        self.rollback_called = False

    def scalar(self, _statement):
        self.scalar_calls += 1
        if self.scalar_calls == 1:
            return self.refresh_session
        return self.user

    def rollback(self) -> None:
        self.rollback_called = True


def build_user() -> User:
    user = User(
        full_name="Ada Lovelace",
        email="ada@example.com",
        password_hash="$argon2id$test-hash",
        role=UserRole.USER,
        is_verified=True,
    )
    user.id = uuid4()
    return user


def build_refresh_session(
    user: User,
    *,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> RefreshToken:
    refresh_session = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(RAW_REFRESH_TOKEN),
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(days=1),
        revoked_at=revoked_at,
    )
    refresh_session.id = uuid4()
    return refresh_session


@pytest.fixture
def jwt_settings() -> Settings:
    return Settings(jwt_secret=SecretStr(TEST_JWT_SECRET))


@pytest.fixture
def refresh_client(jwt_settings):
    def make_client(
        refresh_session: RefreshToken | None,
        user: User | None,
    ) -> tuple[TestClient, FakeRefreshSession]:
        session = FakeRefreshSession(refresh_session, user)
        app.dependency_overrides[get_database_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: jwt_settings
        return TestClient(app), session

    yield make_client
    app.dependency_overrides.clear()


def test_refresh_success(refresh_client, jwt_settings) -> None:
    user = build_user()
    client, session = refresh_client(build_refresh_session(user), user)

    with client:
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == 900
    assert "refresh_token" not in response.json()
    payload = decode_access_token(
        response.json()["access_token"],
        settings=jwt_settings,
    )
    assert payload["sub"] == str(user.id)
    assert payload["sid"] == str(session.refresh_session.id)


def test_invalid_refresh_token_is_rejected(refresh_client) -> None:
    client, session = refresh_client(None, None)

    with client:
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "unknown-refresh-token"},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_refresh_token"
    assert session.rollback_called is True


def test_expired_refresh_token_is_rejected(refresh_client) -> None:
    user = build_user()
    refresh_session = build_refresh_session(
        user,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    client, _ = refresh_client(refresh_session, user)

    with client:
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "refresh_token_expired"


def test_revoked_refresh_token_is_rejected(refresh_client) -> None:
    user = build_user()
    refresh_session = build_refresh_session(
        user,
        revoked_at=datetime.now(timezone.utc),
    )
    client, _ = refresh_client(refresh_session, user)

    with client:
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": RAW_REFRESH_TOKEN},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "refresh_token_revoked"
