"""Public authentication routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_database_session
from app.core.security import hash_password
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User, UserRole
from app.schemas.auth import (
    EmailVerificationRequest,
    EmailVerificationResponse,
    ErrorResponse,
    UserRegistrationRequest,
    UserRegistrationResponse,
)
from app.services.email import EmailDeliveryError, EmailService, get_email_service
from app.services.email_verification import (
    generate_email_verification_token,
    hash_email_verification_token,
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


def email_delivery_unavailable() -> HTTPException:
    """Return a safe response when the verification email cannot be delivered."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "email_delivery_unavailable",
            "message": "Registration is temporarily unavailable.",
        },
    )


def invalid_verification_token() -> HTTPException:
    """Return a safe response for a token that does not exist."""
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "code": "invalid_verification_token",
            "message": "The verification token is invalid.",
        },
    )


def expired_verification_token() -> HTTPException:
    """Return a clear response for an expired token."""
    return HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "code": "verification_token_expired",
            "message": "The verification token has expired.",
        },
    )


def used_verification_token() -> HTTPException:
    """Return a clear response for a token that was already consumed."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": "verification_token_already_used",
            "message": "The verification token has already been used.",
        },
    )


def verification_unavailable() -> HTTPException:
    """Return a safe response when verification cannot reach persistence."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "verification_unavailable",
            "message": "Email verification is temporarily unavailable.",
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


@router.post(
    "/verify-email",
    response_model=EmailVerificationResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_409_CONFLICT: {"model": ErrorResponse},
        status.HTTP_410_GONE: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
def verify_email(
    verification: EmailVerificationRequest,
    session: Session = Depends(get_database_session),
) -> EmailVerificationResponse:
    """Consume a valid token and verify its user in one transaction."""
    token_hash = hash_email_verification_token(
        verification.token.get_secret_value()
    )
    verified_at = datetime.now(timezone.utc)

    try:
        token_record = session.scalar(
            select(EmailVerificationToken)
            .where(EmailVerificationToken.token_hash == token_hash)
            .with_for_update()
        )
        if token_record is None:
            raise invalid_verification_token()
        if token_record.used_at is not None:
            raise used_verification_token()
        if token_record.expires_at <= verified_at:
            raise expired_verification_token()

        user = session.scalar(
            select(User)
            .where(User.id == token_record.user_id)
            .with_for_update()
        )
        if user is None:
            raise invalid_verification_token()

        user.is_verified = True
        token_record.used_at = verified_at
        session.commit()
    except HTTPException:
        session.rollback()
        raise
    except SQLAlchemyError as exc:
        session.rollback()
        raise verification_unavailable() from exc

    return EmailVerificationResponse(
        message="Email verified successfully.",
        is_verified=True,
    )
