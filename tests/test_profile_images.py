"""Focused tests for authenticated profile-image management."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user
from app.api.v1.users import MAX_PROFILE_IMAGE_SIZE, PROFILE_IMAGE_URL
from app.core.database import get_database_session
from app.main import app
from app.models.user import User, UserRole
from app.services.object_storage import StoredObject, get_object_storage_service

PNG_IMAGE = b"\x89PNG\r\n\x1a\n" + b"valid-test-image"


class FakeProfileImageSession:
    """Record profile-image association persistence."""

    def __init__(self) -> None:
        self.commit_called = False
        self.rollback_called = False

    def commit(self) -> None:
        self.commit_called = True

    def rollback(self) -> None:
        self.rollback_called = True


class FakeObjectStorage:
    """Capture object operations without contacting MinIO."""

    def __init__(self) -> None:
        self.uploads: list[tuple[str, bytes, str]] = []
        self.deleted_keys: list[str] = []
        self.requested_keys: list[str] = []

    def upload_object(self, key: str, data: bytes, content_type: str) -> None:
        self.uploads.append((key, data, content_type))

    def delete_object(self, key: str) -> None:
        self.deleted_keys.append(key)

    def get_object(self, key: str) -> StoredObject:
        self.requested_keys.append(key)
        return StoredObject(data=PNG_IMAGE, content_type="image/png")


def build_user(*, profile_image_key: str | None = None) -> User:
    """Build one authenticated user for image tests."""
    timestamp = datetime.now(timezone.utc)
    user = User(
        full_name="Ada MUSANE",
        email="ada.musane@ucbukavu.ac.cd",
        password_hash="$argon2id$private-test-hash",
        role=UserRole.USER,
        is_verified=True,
        profile_image_key=profile_image_key,
    )
    user.id = uuid4()
    user.created_at = timestamp
    user.updated_at = timestamp
    return user


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    """Keep image-test dependencies isolated."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def profile_image_client():
    def make_client(
        *, profile_image_key: str | None = None
    ) -> tuple[TestClient, User, FakeProfileImageSession, FakeObjectStorage]:
        user = build_user(profile_image_key=profile_image_key)
        session = FakeProfileImageSession()
        storage = FakeObjectStorage()
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_database_session] = lambda: session
        app.dependency_overrides[get_object_storage_service] = lambda: storage
        return TestClient(app), user, session, storage

    return make_client


def test_authenticated_profile_image_upload_succeeds(profile_image_client) -> None:
    client, user, session, storage = profile_image_client()

    with client:
        response = client.post(
            "/api/v1/users/me/profile-image",
            files={"image": ("ignored-name.png", PNG_IMAGE, "image/png")},
        )

    assert response.status_code == 200
    assert response.json()["profile_image_url"] == PROFILE_IMAGE_URL
    assert response.json()["profile_image_key"] == user.profile_image_key
    assert user.profile_image_key.startswith(f"users/{user.id}/")
    assert user.profile_image_key.endswith(".png")
    assert "ignored-name" not in user.profile_image_key
    assert storage.uploads == [(user.profile_image_key, PNG_IMAGE, "image/png")]
    assert session.commit_called is True


def test_unauthenticated_profile_image_upload_is_rejected() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/users/me/profile-image",
            files={"image": ("avatar.png", PNG_IMAGE, "image/png")},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_access_token"


def test_unsupported_or_falsely_declared_image_is_rejected(
    profile_image_client,
) -> None:
    client, user, session, storage = profile_image_client()

    with client:
        response = client.post(
            "/api/v1/users/me/profile-image",
            files={"image": ("fake.png", b"not really an image", "image/png")},
        )

    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "unsupported_profile_image"
    assert user.profile_image_key is None
    assert storage.uploads == []
    assert session.commit_called is False


def test_oversized_profile_image_is_rejected(profile_image_client) -> None:
    client, user, session, storage = profile_image_client()
    oversized_image = b"\x89PNG\r\n\x1a\n" + b"x" * MAX_PROFILE_IMAGE_SIZE

    with client:
        response = client.post(
            "/api/v1/users/me/profile-image",
            files={"image": ("large.png", oversized_image, "image/png")},
        )

    assert response.status_code == 413
    assert user.profile_image_key is None
    assert storage.uploads == []
    assert session.commit_called is False


def test_replacement_updates_association_and_deletes_previous_object(
    profile_image_client,
) -> None:
    previous_key = "users/existing/previous.jpg"
    client, user, session, storage = profile_image_client(
        profile_image_key=previous_key
    )

    with client:
        response = client.post(
            "/api/v1/users/me/profile-image",
            files={"image": ("replacement.png", PNG_IMAGE, "image/png")},
        )

    assert response.status_code == 200
    assert user.profile_image_key != previous_key
    assert response.json()["profile_image_key"] == user.profile_image_key
    assert storage.uploads[0][0] == user.profile_image_key
    assert storage.deleted_keys == [previous_key]
    assert session.commit_called is True


def test_profile_exposes_authenticated_image_url(profile_image_client) -> None:
    client, user, _, _ = profile_image_client(
        profile_image_key="users/existing/avatar.webp"
    )

    with client:
        response = client.get("/api/v1/users/me")

    assert response.status_code == 200
    assert response.json()["profile_image_key"] == user.profile_image_key
    assert response.json()["profile_image_url"] == PROFILE_IMAGE_URL


def test_authenticated_profile_image_can_be_served(profile_image_client) -> None:
    image_key = "users/existing/avatar.png"
    client, _, _, storage = profile_image_client(profile_image_key=image_key)

    with client:
        response = client.get("/api/v1/users/me/profile-image")

    assert response.status_code == 200
    assert response.content == PNG_IMAGE
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == "private, max-age=300"
    assert storage.requested_keys == [image_key]
