"""Focused tests for the administrator user listing."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user
from app.core.database import get_database_session
from app.main import app
from app.models.user import User, UserRole


class FakeScalarResult:
    """Return configured ORM rows from a fake scalar query."""

    def __init__(self, users: list[User]) -> None:
        self.users = users

    def all(self) -> list[User]:
        return self.users


class CapturingAdminSession:
    """Capture count and list statements without requiring PostgreSQL."""

    def __init__(self, users: list[User], total: int | None = None) -> None:
        self.users = users
        self.total = len(users) if total is None else total
        self.count_statement = None
        self.list_statement = None

    def scalar(self, statement):
        self.count_statement = statement
        return self.total

    def scalars(self, statement) -> FakeScalarResult:
        self.list_statement = statement
        return FakeScalarResult(self.users)


def build_user(
    *,
    full_name: str,
    role: UserRole = UserRole.USER,
    is_verified: bool = True,
    created_offset: int = 0,
) -> User:
    """Build a safe response-compatible user."""
    timestamp = datetime.now(timezone.utc) + timedelta(seconds=created_offset)
    user = User(
        full_name=full_name,
        email=f"{full_name.lower().replace(' ', '.')}@example.com",
        password_hash="$argon2id$private-test-hash",
        role=role,
        is_verified=is_verified,
        profile_image_key=None,
    )
    user.id = uuid4()
    user.created_at = timestamp
    user.updated_at = timestamp
    return user


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    """Keep dependency overrides isolated between listing tests."""
    yield
    app.dependency_overrides.clear()


def configure_access(current_user: User, session: CapturingAdminSession) -> None:
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_database_session] = lambda: session


def test_administrator_can_list_safe_users() -> None:
    administrator = build_user(full_name="Admin User", role=UserRole.ADMIN)
    listed_user = build_user(full_name="Ada Musane")
    session = CapturingAdminSession([listed_user])
    configure_access(administrator, session)

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["email"] == listed_user.email
    assert "password_hash" not in response.json()["items"][0]


def test_regular_user_receives_forbidden() -> None:
    user = build_user(full_name="Regular User")
    session = CapturingAdminSession([])
    configure_access(user, session)

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "administrator_access_required"
    assert session.list_statement is None


def test_unauthenticated_admin_user_listing_is_rejected() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_access_token"


def test_user_listing_pagination() -> None:
    administrator = build_user(full_name="Admin User", role=UserRole.ADMIN)
    page_users = [build_user(full_name="User Three"), build_user(full_name="User Four")]
    session = CapturingAdminSession(page_users, total=5)
    configure_access(administrator, session)

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users?page=2&page_size=2")

    assert response.status_code == 200
    assert response.json()["page"] == 2
    assert response.json()["page_size"] == 2
    assert response.json()["total"] == 5
    assert response.json()["total_pages"] == 3
    assert session.list_statement._offset_clause.value == 2
    assert session.list_statement._limit_clause.value == 2


def test_user_listing_filters_by_role() -> None:
    administrator = build_user(full_name="Admin User", role=UserRole.ADMIN)
    session = CapturingAdminSession([administrator])
    configure_access(administrator, session)

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users?role=ADMIN")

    assert response.status_code == 200
    params = session.list_statement.compile().params.values()
    assert UserRole.ADMIN in params
    assert "users.role" in str(session.list_statement)


def test_user_listing_filters_by_verification_status() -> None:
    administrator = build_user(full_name="Admin User", role=UserRole.ADMIN)
    unverified_user = build_user(full_name="Pending User", is_verified=False)
    session = CapturingAdminSession([unverified_user])
    configure_access(administrator, session)

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users?is_verified=false")

    assert response.status_code == 200
    assert "users.is_verified = false" in str(session.list_statement).lower()


def test_user_listing_uses_allowlisted_sorting() -> None:
    administrator = build_user(full_name="Admin User", role=UserRole.ADMIN)
    session = CapturingAdminSession([])
    configure_access(administrator, session)

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/admin/users?sort_by=full_name&sort_order=asc"
        )

    assert response.status_code == 200
    assert "ORDER BY users.full_name ASC" in str(session.list_statement)


def test_arbitrary_sort_column_is_rejected() -> None:
    administrator = build_user(full_name="Admin User", role=UserRole.ADMIN)
    session = CapturingAdminSession([])
    configure_access(administrator, session)

    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users?sort_by=password_hash")

    assert response.status_code == 422
    assert session.list_statement is None
