"""Focused tests for consuming email verification tokens."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_database_session
from app.main import app
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User, UserRole
from app.services.email_verification import hash_email_verification_token

RAW_TOKEN = "test-email-verification-token"


class FakeVerificationSession:
    """Provide token and user rows to the verification endpoint in query order."""

    def __init__(
        self,
        token_record: EmailVerificationToken | None,
        user: User | None,
    ) -> None:
        self.token_record = token_record
        self.user = user
        self.scalar_calls = 0
        self.commit_called = False
        self.rollback_called = False

    def scalar(self, _statement):
        self.scalar_calls += 1
        if self.scalar_calls == 1:
            return self.token_record
        return self.user

    def commit(self) -> None:
        self.commit_called = True

    def rollback(self) -> None:
        self.rollback_called = True


def build_user() -> User:
    user = User(
        full_name="Ada Lovelace",
        email="ada@example.com",
        password_hash="$argon2id$test-hash",
        role=UserRole.USER,
        is_verified=False,
    )
    user.id = uuid4()
    return user


def build_token(
    user: User,
    *,
    expires_at: datetime | None = None,
    used_at: datetime | None = None,
) -> EmailVerificationToken:
    return EmailVerificationToken(
        user_id=user.id,
        token_hash=hash_email_verification_token(RAW_TOKEN),
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(hours=1),
        used_at=used_at,
    )


@pytest.fixture
def verification_client():
    sessions: list[FakeVerificationSession] = []

    def make_client(session: FakeVerificationSession):
        sessions.append(session)
        app.dependency_overrides[get_database_session] = lambda: session
        return TestClient(app)

    yield make_client
    app.dependency_overrides.clear()


def test_valid_verification(verification_client) -> None:
    user = build_user()
    token_record = build_token(user)
    session = FakeVerificationSession(token_record, user)

    with verification_client(session) as client:
        response = client.post("/api/v1/auth/verify-email", json={"token": RAW_TOKEN})

    assert response.status_code == 200
    assert response.json() == {
        "message": "Email verified successfully.",
        "is_verified": True,
    }
    assert token_record.used_at is not None
    assert session.commit_called is True


def test_invalid_token(verification_client) -> None:
    session = FakeVerificationSession(None, None)

    with verification_client(session) as client:
        response = client.post("/api/v1/auth/verify-email", json={"token": "unknown"})

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_verification_token"
    assert session.rollback_called is True


def test_expired_token(verification_client) -> None:
    user = build_user()
    token_record = build_token(
        user,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    session = FakeVerificationSession(token_record, user)

    with verification_client(session) as client:
        response = client.post("/api/v1/auth/verify-email", json={"token": RAW_TOKEN})

    assert response.status_code == 410
    assert response.json()["detail"]["code"] == "verification_token_expired"
    assert session.commit_called is False


def test_already_used_token(verification_client) -> None:
    user = build_user()
    token_record = build_token(user, used_at=datetime.now(timezone.utc))
    session = FakeVerificationSession(token_record, user)

    with verification_client(session) as client:
        response = client.post("/api/v1/auth/verify-email", json={"token": RAW_TOKEN})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "verification_token_already_used"
    assert session.commit_called is False


def test_user_becomes_verified_after_success(verification_client) -> None:
    user = build_user()
    session = FakeVerificationSession(build_token(user), user)

    with verification_client(session) as client:
        response = client.post("/api/v1/auth/verify-email", json={"token": RAW_TOKEN})

    assert response.status_code == 200
    assert user.is_verified is True
