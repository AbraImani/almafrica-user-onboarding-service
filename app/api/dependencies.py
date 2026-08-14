"""Reusable API authentication dependencies."""

from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import get_database_session
from app.core.rate_limit import InMemoryRateLimiter
from app.core.security import (
    AccessTokenError,
    JWTConfigurationError,
    decode_access_token,
)
from app.models.user import User, UserRole

bearer_scheme = HTTPBearer(auto_error=False)
settings = get_settings()
login_rate_limiter = InMemoryRateLimiter(
    limit=settings.login_rate_limit_attempts,
    window_seconds=settings.login_rate_limit_window_seconds,
)


def get_login_rate_limiter() -> InMemoryRateLimiter:
    """Return the process-local login limiter."""
    return login_rate_limiter


def enforce_login_rate_limit(
    request: Request,
    limiter: InMemoryRateLimiter = Depends(get_login_rate_limiter),
) -> None:
    """Limit login attempts by the directly connected client IP address."""
    client_ip = request.client.host if request.client is not None else "unknown"
    decision = limiter.check(client_ip)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "login_rate_limit_exceeded",
                "message": "Too many login attempts. Try again later.",
            },
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


def invalid_access_token() -> HTTPException:
    """Return one response for absent, malformed, expired, or unknown tokens."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "invalid_access_token",
            "message": "A valid access token is required.",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def authentication_unavailable() -> HTTPException:
    """Return a safe response for authentication infrastructure failures."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "authentication_unavailable",
            "message": "Authentication is temporarily unavailable.",
        },
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: Session = Depends(get_database_session),
    settings: Settings = Depends(get_settings),
) -> User:
    """Resolve a current database user from a signed Bearer access token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise invalid_access_token()

    try:
        payload = decode_access_token(credentials.credentials, settings=settings)
        user_id = UUID(payload["sub"])
    except (AccessTokenError, KeyError, TypeError, ValueError):
        raise invalid_access_token()
    except JWTConfigurationError as exc:
        raise authentication_unavailable() from exc

    try:
        user = session.scalar(select(User).where(User.id == user_id))
    except SQLAlchemyError as exc:
        raise authentication_unavailable() from exc

    if user is None:
        raise invalid_access_token()
    if user.role == UserRole.USER and not user.is_verified:
        raise invalid_access_token()
    return user
