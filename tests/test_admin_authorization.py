"""Focused tests for reusable administrator authorization."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user
from app.main import app
from app.models.user import User, UserRole


def build_user(role: UserRole) -> User:
    """Build an authenticated user with the requested role."""
    user = User(
        full_name=f"Test {role.value}",
        email=f"{role.value.lower()}@example.com",
        password_hash="$argon2id$private-test-hash",
        role=role,
        is_verified=True,
        profile_image_key=None,
    )
    user.id = uuid4()
    user.created_at = datetime.now(timezone.utc)
    user.updated_at = user.created_at
    return user


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    """Keep authentication overrides isolated between authorization tests."""
    yield
    app.dependency_overrides.clear()


def test_administrator_is_accepted() -> None:
    administrator = build_user(UserRole.ADMIN)
    app.dependency_overrides[get_current_user] = lambda: administrator

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/access-check")

    assert response.status_code == 200
    assert response.json() == {"message": "Administrator access granted."}


def test_regular_user_receives_forbidden() -> None:
    user = build_user(UserRole.USER)
    app.dependency_overrides[get_current_user] = lambda: user

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/access-check")

    assert response.status_code == 403
    assert response.json() == {
        "detail": {
            "code": "administrator_access_required",
            "message": "Administrator access is required.",
        }
    }


def test_unauthenticated_caller_uses_normal_authentication_failure() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/access-check")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_access_token"
