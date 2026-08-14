"""End-to-end security behavior of the core onboarding flow."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api.dependencies import get_login_rate_limiter
from app.core.config import Settings, get_settings
from app.core.database import get_database_session
from app.core.rate_limit import InMemoryRateLimiter
from app.main import app
from app.models.email_verification_token import EmailVerificationToken
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.services.email import get_email_service

TEST_EMAIL = "security.flow@example.com"
TEST_PASSWORD = "SecureFlowPassword24"
TEST_JWT_SECRET = "test-only-onboarding-flow-secret-at-least-32-chars"


class CapturingEmailService:
    """Capture the raw verification token as the recipient would receive it."""

    def __init__(self) -> None:
        self.delivery: dict | None = None

    def send_verification_email(self, **delivery) -> None:
        self.delivery = delivery


class OnboardingSession:
    """Persist one onboarding flow across multiple HTTP requests in memory."""

    def __init__(self) -> None:
        self.user: User | None = None
        self.verification_token: EmailVerificationToken | None = None
        self.refresh_session: RefreshToken | None = None

    def scalar(self, statement):
        description = statement.column_descriptions[0]
        entity = description.get("entity")
        expression = description.get("expr")

        if entity is EmailVerificationToken:
            return self.verification_token
        if entity is RefreshToken:
            return self.refresh_session
        if entity is User and getattr(expression, "key", None) == "id":
            return None if self.user is None else self.user.id
        if entity is User:
            return self.user
        return None

    def add(self, instance) -> None:
        if isinstance(instance, User):
            self.user = instance
        elif isinstance(instance, EmailVerificationToken):
            self.verification_token = instance
        elif isinstance(instance, RefreshToken):
            self.refresh_session = instance

    def flush(self) -> None:
        if self.user is not None and self.user.id is None:
            self.user.id = uuid4()
        if self.verification_token is not None and self.verification_token.id is None:
            self.verification_token.id = uuid4()
        if self.refresh_session is not None and self.refresh_session.id is None:
            self.refresh_session.id = uuid4()

    def commit(self) -> None:
        return None

    def refresh(self, user: User) -> None:
        timestamp = datetime.now(timezone.utc)
        user.created_at = timestamp
        user.updated_at = timestamp

    def rollback(self) -> None:
        return None


@pytest.fixture
def onboarding_client():
    session = OnboardingSession()
    email_service = CapturingEmailService()
    settings = Settings(jwt_secret=SecretStr(TEST_JWT_SECRET))
    limiter = InMemoryRateLimiter(limit=20, window_seconds=60)

    app.dependency_overrides[get_database_session] = lambda: session
    app.dependency_overrides[get_email_service] = lambda: email_service
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_login_rate_limiter] = lambda: limiter

    with TestClient(app) as client:
        yield client, session, email_service

    app.dependency_overrides.clear()


def test_registration_verification_login_and_protected_access(
    onboarding_client,
) -> None:
    client, session, email_service = onboarding_client

    registration = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Security Flow User",
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
        },
    )

    assert registration.status_code == 201
    assert registration.json()["is_verified"] is False
    assert session.user is not None
    assert session.user.is_verified is False
    assert email_service.delivery is not None

    unverified_login = client.post(
        "/api/v1/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert unverified_login.status_code == 403
    assert unverified_login.json()["detail"]["code"] == "email_not_verified"

    verification = client.post(
        "/api/v1/auth/verify-email",
        json={"token": email_service.delivery["raw_token"]},
    )

    assert verification.status_code == 200
    assert verification.json()["is_verified"] is True
    assert session.user.is_verified is True

    invalid_login = client.post(
        "/api/v1/auth/login",
        json={"email": TEST_EMAIL, "password": "WrongPassword24"},
    )

    assert invalid_login.status_code == 401
    assert invalid_login.json()["detail"]["code"] == "invalid_credentials"

    valid_login = client.post(
        "/api/v1/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert valid_login.status_code == 200
    assert valid_login.json()["token_type"] == "bearer"
    assert session.refresh_session is not None

    profile = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {valid_login.json()['access_token']}"},
    )

    assert profile.status_code == 200
    assert profile.json()["id"] == str(session.user.id)
    assert profile.json()["email"] == TEST_EMAIL
    assert "password_hash" not in profile.json()
