"""Focused tests for login and Bearer access-token authentication."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.core.database import get_database_session
from app.core.security import create_access_token, decode_access_token, hash_password
from app.main import app
from app.models.user import User, UserRole

TEST_PASSWORD = "correct-password-123"
TEST_JWT_SECRET = "test-only-jwt-secret-with-at-least-32-characters"
TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)


class FakeSession:
    """Return one configured user for login and current-user lookups."""

    def __init__(self, user: User | None) -> None:
        self.user = user

    def scalar(self, _statement):
        return self.user


def build_user(*, is_verified: bool = True) -> User:
    user = User(
        full_name="Ada Lovelace",
        email="ada@example.com",
        password_hash=TEST_PASSWORD_HASH,
        role=UserRole.USER,
        is_verified=is_verified,
    )
    user.id = uuid4()
    user.created_at = datetime.now(timezone.utc)
    user.updated_at = user.created_at
    return user


@pytest.fixture
def jwt_settings() -> Settings:
    return Settings(jwt_secret=SecretStr(TEST_JWT_SECRET))


@pytest.fixture
def authentication_client(jwt_settings):
    def make_client(user: User | None):
        session = FakeSession(user)
        app.dependency_overrides[get_database_session] = lambda: session
        app.dependency_overrides[get_settings] = lambda: jwt_settings
        return TestClient(app)

    yield make_client
    app.dependency_overrides.clear()


def login_payload(*, password: str = TEST_PASSWORD) -> dict[str, str]:
    return {
        "email": "  ADA@EXAMPLE.COM  ",
        "password": password,
    }


def test_successful_login(authentication_client, jwt_settings) -> None:
    user = build_user()

    with authentication_client(user) as client:
        response = client.post("/api/v1/auth/login", json=login_payload())

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == 900
    payload = decode_access_token(
        response.json()["access_token"],
        settings=jwt_settings,
    )
    assert payload["sub"] == str(user.id)
    assert payload["role"] == "USER"
    assert "iat" in payload
    assert "exp" in payload


def test_wrong_password_returns_generic_error(authentication_client) -> None:
    with authentication_client(build_user()) as client:
        response = client.post(
            "/api/v1/auth/login",
            json=login_payload(password="wrong-password-456"),
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_credentials"


def test_unknown_email_returns_same_generic_error(authentication_client) -> None:
    with authentication_client(None) as client:
        response = client.post("/api/v1/auth/login", json=login_payload())

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_credentials"


def test_unverified_user_is_rejected(authentication_client) -> None:
    with authentication_client(build_user(is_verified=False)) as client:
        response = client.post("/api/v1/auth/login", json=login_payload())

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "email_not_verified"


@pytest.mark.parametrize("access_token", ["not-a-jwt", ""])
def test_invalid_access_token_is_rejected(
    authentication_client,
    access_token,
) -> None:
    with authentication_client(build_user()) as client:
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_access_token"


def test_expired_access_token_is_rejected(authentication_client, jwt_settings) -> None:
    user = build_user()
    expired_token, _ = create_access_token(
        user_id=user.id,
        role=user.role,
        settings=jwt_settings,
        now=datetime.now(timezone.utc) - timedelta(minutes=16),
    )

    with authentication_client(user) as client:
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_access_token"


def test_valid_token_resolves_current_user(authentication_client, jwt_settings) -> None:
    user = build_user()
    access_token, _ = create_access_token(
        user_id=user.id,
        role=user.role,
        settings=jwt_settings,
    )

    with authentication_client(user) as client:
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 200
    assert response.json()["id"] == str(user.id)
    assert response.json()["email"] == user.email
    assert "password_hash" not in response.json()
