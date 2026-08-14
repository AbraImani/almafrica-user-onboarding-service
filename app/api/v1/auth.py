"""Public authentication routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_database_session
from app.core.security import hash_password
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User, UserRole
from app.schemas.auth import (
    ErrorResponse,
    UserRegistrationRequest,
    UserRegistrationResponse,
)
from app.services.email import EmailDeliveryError, EmailService, get_email_service
from app.services.email_verification import generate_email_verification_token

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


def email_delivery_unavailable() -> HTTPException:
    """Return a safe response when the verification email cannot be delivered."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "email_delivery_unavailable",
            "message": "Registration is temporarily unavailable.",
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
    email_service: EmailService = Depends(get_email_service),
) -> User:
    """Register an unverified user and deliver a single-use verification link."""
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
        session.flush()

        generated_token = generate_email_verification_token()
        verification_token = EmailVerificationToken(
            user_id=user.id,
            token_hash=generated_token.token_hash,
            expires_at=generated_token.expires_at,
        )
        session.add(verification_token)
        session.flush()

        email_service.send_verification_email(
            recipient_email=user.email,
            recipient_name=user.full_name,
            raw_token=generated_token.raw_token,
            expires_at=generated_token.expires_at,
        )
        session.commit()
        session.refresh(user)
    except EmailDeliveryError as exc:
        session.rollback()
        raise email_delivery_unavailable() from exc
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
