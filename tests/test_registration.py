"""Focused tests for public user registration."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from app.core.database import get_database_session
from app.main import app
from app.models.user import User


class FakeSession:
    """Minimal session behavior needed by the registration endpoint."""

    def __init__(self, existing_user_id=None) -> None:
        self.existing_user_id = existing_user_id
        self.added_user: User | None = None
        self.rollback_called = False

    def scalar(self, _statement):
        return self.existing_user_id

    def add(self, user: User) -> None:
        self.added_user = user

    def commit(self) -> None:
        return None

    def refresh(self, user: User) -> None:
        user.id = uuid4()
        user.created_at = datetime.now(timezone.utc)
        user.updated_at = user.created_at

    def rollback(self) -> None:
        self.rollback_called = True


@pytest.fixture
def registration_client():
    session = FakeSession()
    app.dependency_overrides[get_database_session] = lambda: session
    with TestClient(app) as client:
        yield client, session
    app.dependency_overrides.clear()


def valid_registration() -> dict[str, str]:
    return {
        "full_name": "  Ada Lovelace  ",
        "email": "  Ada.Lovelace@Example.COM  ",
        "password": "practical-password-123",
    }


def test_successful_registration(registration_client) -> None:
    client, session = registration_client

    response = client.post("/api/v1/auth/register", json=valid_registration())

    assert response.status_code == 201
    assert response.json()["full_name"] == "Ada Lovelace"
    assert response.json()["email"] == "ada.lovelace@example.com"
    assert response.json()["role"] == "USER"
    assert response.json()["is_verified"] is False
    assert "password" not in response.json()
    assert "password_hash" not in response.json()
    assert session.added_user is not None


def test_duplicate_email_returns_conflict(registration_client) -> None:
    client, session = registration_client
    session.existing_user_id = uuid4()

    response = client.post("/api/v1/auth/register", json=valid_registration())

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "email_already_registered",
            "message": "A user with this email already exists.",
        }
    }
    assert session.added_user is None


def test_invalid_email_returns_validation_error(registration_client) -> None:
    client, _ = registration_client
    payload = valid_registration()
    payload["email"] = "not-an-email"

    response = client.post("/api/v1/auth/register", json=payload)

    assert response.status_code == 422


def test_invalid_password_returns_validation_error(registration_client) -> None:
    client, _ = registration_client
    payload = valid_registration()
    payload["password"] = "letters-only-password"

    response = client.post("/api/v1/auth/register", json=payload)

    assert response.status_code == 422


def test_password_is_hashed_before_persistence(registration_client) -> None:
    client, session = registration_client
    payload = valid_registration()

    response = client.post("/api/v1/auth/register", json=payload)

    assert response.status_code == 201
    assert session.added_user is not None
    assert session.added_user.password_hash != payload["password"]
    assert session.added_user.password_hash.startswith("$argon2id$")
    assert PasswordHasher().verify(
        session.added_user.password_hash,
        payload["password"],
    )
