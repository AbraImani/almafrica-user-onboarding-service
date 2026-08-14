"""Password and access-token security helpers."""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import Settings
from app.models.user import UserRole

_password_hasher = PasswordHasher()
_dummy_password_hash = _password_hasher.hash(secrets.token_urlsafe(32))


class AccessTokenError(Exception):
    """Raised when an access token is missing required claims or is invalid."""


class JWTConfigurationError(Exception):
    """Raised when JWT signing has not been configured."""


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2id."""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without propagating malformed-hash details."""
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def verify_dummy_password(password: str) -> None:
    """Perform Argon2 work when no user exists to reduce timing differences."""
    verify_password(password, _dummy_password_hash)


def create_access_token(
    *,
    user_id: UUID,
    role: UserRole,
    settings: Settings,
    now: datetime | None = None,
) -> tuple[str, int]:
    """Create a signed, short-lived JWT access token."""
    secret = _jwt_secret(settings)
    issued_at = now or datetime.now(timezone.utc)
    expires_in = settings.jwt_access_token_expire_minutes * 60
    expires_at = issued_at + timedelta(seconds=expires_in)
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "iat": issued_at,
        "exp": expires_at,
    }
    token = jwt.encode(
        payload,
        secret,
        algorithm=settings.jwt_algorithm,
    )
    return token, expires_in


def decode_access_token(token: str, *, settings: Settings) -> dict[str, Any]:
    """Validate an access token and require its identity and time claims."""
    secret = _jwt_secret(settings)
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "iat", "exp"]},
        )
    except jwt.InvalidTokenError as exc:
        raise AccessTokenError("Invalid access token") from exc


def _jwt_secret(settings: Settings) -> str:
    """Return the configured signing secret or fail without a fallback secret."""
    if settings.jwt_secret is None:
        raise JWTConfigurationError("JWT secret is not configured")
    return settings.jwt_secret.get_secret_value()
