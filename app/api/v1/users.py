"""Authenticated user routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.database import get_database_session
from app.models.user import User
from app.schemas.auth import CurrentUserResponse, ErrorResponse, UserProfileUpdateRequest

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
