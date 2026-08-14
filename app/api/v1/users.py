"""Authenticated user routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
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
    UserProfileUpdateRequest,
)

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=CurrentUserResponse)
def get_authenticated_user(current_user: User = Depends(get_current_user)) -> User:
    """Return the safe profile of the authenticated user."""
    return current_user


@router.patch(
    "/me",
    response_model=CurrentUserResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse}},
)
def update_authenticated_user(
    update: UserProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_database_session),
) -> User:
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

    return current_user


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
