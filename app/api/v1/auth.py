"""Public authentication routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_database_session
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.schemas.auth import (
    ErrorResponse,
    UserRegistrationRequest,
    UserRegistrationResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def email_conflict() -> HTTPException:
    """Return the consistent duplicate-email response."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": "email_already_registered",
            "message": "A user with this email already exists.",
        },
    )


def database_unavailable() -> HTTPException:
    """Return a safe response for database failures."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "database_unavailable",
            "message": "Registration is temporarily unavailable.",
        },
    )


def registration_failed() -> HTTPException:
    """Return a safe response for an unexpected persistence conflict."""
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "code": "registration_failed",
            "message": "Unable to complete registration.",
        },
    )


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponse,
    responses={
        status.HTTP_409_CONFLICT: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
def register_user(
    registration: UserRegistrationRequest,
    session: Session = Depends(get_database_session),
) -> User:
    """Register an unverified user with a securely hashed password."""
    normalized_email = str(registration.email)

    try:
        existing_user_id = session.scalar(
            select(User.id).where(User.email == normalized_email)
        )
        if existing_user_id is not None:
            raise email_conflict()

        user = User(
            full_name=registration.full_name,
            email=normalized_email,
            password_hash=hash_password(registration.password.get_secret_value()),
            role=UserRole.USER,
            is_verified=False,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    except IntegrityError as exc:
        session.rollback()
        try:
            duplicate_user_id = session.scalar(
                select(User.id).where(User.email == normalized_email)
            )
        except SQLAlchemyError as exc:
            raise database_unavailable() from exc
        if duplicate_user_id is not None:
            raise email_conflict()
        raise registration_failed() from exc
    except SQLAlchemyError as exc:
        session.rollback()
        raise database_unavailable() from exc

    return user
