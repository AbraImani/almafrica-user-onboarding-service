"""Focused tests for authenticated self-profile management."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user
from app.core.database import get_database_session
from app.main import app
from app.models.user import User, UserRole


class FakeProfileSession:
    """Persist and refresh one in-memory authenticated user."""

    def __init__(self) -> None:
        self.commit_called = False
        self.rollback_called = False

    def commit(self) -> None:
        self.commit_called = True

    def refresh(self, user: User) -> None:
        user.updated_at = datetime.now(timezone.utc)

    def rollback(self) -> None:
        self.rollback_called = True


def build_user() -> User:
    user = User(
        full_name="Ada MUSANE",
        email="ada.musane@ucbukavu.ac.cd",
        password_hash="$argon2id$private-test-hash",
        role=UserRole.USER,
        is_verified=True,
        profile_image_key=None,
    )
    user.id = uuid4()
    user.created_at = datetime.now(timezone.utc)
    user.updated_at = user.created_at
    return user


@pytest.fixture
def profile_client():
    def make_client() -> tuple[TestClient, User, FakeProfileSession]:
        user = build_user()
        session = FakeProfileSession()
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_database_session] = lambda: session
        return TestClient(app), user, session

    yield make_client
    app.dependency_overrides.clear()


def test_authenticated_user_can_read_own_profile(profile_client) -> None:
    client, user, _ = profile_client()

    with client:
        response = client.get("/api/v1/users/me")

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "full_name": "Ada MUSANE",
        "email": "ada.musane@ucbukavu.ac.cd",
        "role": "USER",
        "is_verified": True,
        "profile_image_key": None,
        "created_at": user.created_at.isoformat().replace("+00:00", "Z"),
        "updated_at": user.updated_at.isoformat().replace("+00:00", "Z"),
    }
    assert "password_hash" not in response.json()


def test_unauthenticated_request_is_rejected() -> None:
    app.dependency_overrides.clear()

    with TestClient(app) as client:
        response = client.get("/api/v1/users/me")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_access_token"


def test_authenticated_user_can_update_own_name(profile_client) -> None:
    client, user, session = profile_client()

    with client:
        response = client.patch(
            "/api/v1/users/me",
            json={"full_name": "  Ada Musane Updated  "},
        )

    assert response.status_code == 200
    assert response.json()["full_name"] == "Ada Musane Updated"
    assert user.full_name == "Ada Musane Updated"
    assert session.commit_called is True


def test_email_cannot_be_changed(profile_client) -> None:
    client, user, session = profile_client()

    with client:
        response = client.patch(
            "/api/v1/users/me",
            json={
                "full_name": "Ada MUSANE",
                "email": "attacker@example.com",
            },
        )

    assert response.status_code == 422
    assert user.email == "ada.musane@ucbukavu.ac.cd"
    assert session.commit_called is False


def test_role_cannot_be_changed(profile_client) -> None:
    client, user, session = profile_client()

    with client:
        response = client.patch(
            "/api/v1/users/me",
            json={"full_name": "Ada MUSANE", "role": "ADMIN"},
        )

    assert response.status_code == 422
    assert user.role == UserRole.USER
    assert session.commit_called is False
