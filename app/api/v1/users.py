"""Authenticated user routes."""

from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import CurrentUserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=CurrentUserResponse)
def get_authenticated_user(current_user: User = Depends(get_current_user)) -> User:
    """Return the safe profile of the authenticated user."""
    return current_user
