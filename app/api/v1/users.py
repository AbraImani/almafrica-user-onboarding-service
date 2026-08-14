"""Authenticated user routes."""

from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.database import get_database_session
from app.core.security import hash_password, verify_password
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    ErrorResponse,
    PasswordChangeRequest,
    PasswordChangeResponse,
    ProfileImageResponse,
    UserProfileUpdateRequest,
)
from app.services.object_storage import (
    ObjectStorageError,
    ObjectStorageService,
    get_object_storage_service,
)

router = APIRouter(prefix="/users", tags=["users"])

MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024
PROFILE_IMAGE_URL = "/api/v1/users/me/profile-image"
_IMAGE_EXTENSIONS = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}


def _current_user_response(user: User) -> CurrentUserResponse:
    """Add the authenticated delivery URL when a profile image exists."""
    response = CurrentUserResponse.model_validate(user)
    if user.profile_image_key is None:
        return response
    return response.model_copy(update={"profile_image_url": PROFILE_IMAGE_URL})


def _detected_image_content_type(data: bytes) -> str | None:
    """Identify supported images from magic bytes rather than filenames."""
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image/webp"
    return None


@router.get("/me", response_model=CurrentUserResponse)
def get_authenticated_user(
    current_user: User = Depends(get_current_user),
) -> CurrentUserResponse:
    """Return the safe profile of the authenticated user."""
    return _current_user_response(current_user)


@router.patch(
    "/me",
    response_model=CurrentUserResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse}},
)
def update_authenticated_user(
    update: UserProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_database_session),
) -> CurrentUserResponse:
    """Update only the authenticated user's explicitly permitted profile field."""
    current_user.full_name = update.full_name

    try:
        session.commit()
        session.refresh(current_user)
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "profile_update_unavailable",
                "message": "Profile update is temporarily unavailable.",
            },
        ) from exc

    return _current_user_response(current_user)


@router.post(
    "/me/change-password",
    response_model=PasswordChangeResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
def change_authenticated_user_password(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_database_session),
) -> PasswordChangeResponse:
    """Change the password and revoke every existing session atomically."""
    current_password = password_change.current_password.get_secret_value()
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "current_password_incorrect",
                "message": "The current password is incorrect.",
            },
        )

    changed_at = datetime.now(timezone.utc)
    current_user.password_hash = hash_password(
        password_change.new_password.get_secret_value()
    )

    try:
        session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == current_user.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=changed_at)
        )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "password_change_unavailable",
                "message": "Password change is temporarily unavailable.",
            },
        ) from exc

    return PasswordChangeResponse(
        message="Password changed successfully. Please sign in again."
    )


@router.post(
    "/me/profile-image",
    response_model=ProfileImageResponse,
    responses={
        413: {"model": ErrorResponse},
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
async def upload_profile_image(
    image: Annotated[UploadFile, File(description="JPEG, PNG, or WebP; max 5 MB")],
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_database_session),
    storage: ObjectStorageService = Depends(get_object_storage_service),
) -> ProfileImageResponse:
    """Upload and associate a validated private profile image."""
    supplied_content_type = (image.content_type or "").split(";", 1)[0].lower()
    contents = await image.read(MAX_PROFILE_IMAGE_SIZE + 1)
    if len(contents) > MAX_PROFILE_IMAGE_SIZE:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "profile_image_too_large",
                "message": "Profile images must not exceed 5 MB.",
            },
        )

    detected_content_type = _detected_image_content_type(contents)
    if (
        supplied_content_type not in _IMAGE_EXTENSIONS
        or detected_content_type != supplied_content_type
    ):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "code": "unsupported_profile_image",
                "message": "Only valid JPEG, PNG, and WebP images are accepted.",
            },
        )

    extension = _IMAGE_EXTENSIONS[detected_content_type]
    new_key = f"users/{current_user.id}/{uuid4()}.{extension}"
    previous_key = current_user.profile_image_key

    try:
        storage.upload_object(new_key, contents, detected_content_type)
    except ObjectStorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "profile_image_storage_unavailable",
                "message": "Profile image storage is temporarily unavailable.",
            },
        ) from exc

    current_user.profile_image_key = new_key
    try:
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        current_user.profile_image_key = previous_key
        try:
            storage.delete_object(new_key)
        except ObjectStorageError:
            pass
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "profile_image_update_unavailable",
                "message": "Profile image update is temporarily unavailable.",
            },
        ) from exc

    if previous_key is not None:
        try:
            storage.delete_object(previous_key)
        except ObjectStorageError:
            pass

    return ProfileImageResponse(
        profile_image_key=new_key,
        profile_image_url=PROFILE_IMAGE_URL,
    )


@router.get(
    "/me/profile-image",
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
def get_profile_image(
    current_user: User = Depends(get_current_user),
    storage: ObjectStorageService = Depends(get_object_storage_service),
) -> Response:
    """Serve the authenticated user's private profile image."""
    if current_user.profile_image_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "profile_image_not_found",
                "message": "No profile image is configured.",
            },
        )
    try:
        stored_object = storage.get_object(current_user.profile_image_key)
    except ObjectStorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "profile_image_storage_unavailable",
                "message": "Profile image storage is temporarily unavailable.",
            },
        ) from exc
    return Response(
        content=stored_object.data,
        media_type=stored_object.content_type,
        headers={"Cache-Control": "private, max-age=300"},
    )
