"""Secure email verification token generation."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

EMAIL_VERIFICATION_TOKEN_BYTES = 32
EMAIL_VERIFICATION_TOKEN_TTL = timedelta(hours=24)


@dataclass(frozen=True)
class GeneratedEmailVerificationToken:
    """Raw delivery value and persistence-safe token data."""

    raw_token: str
    token_hash: str
    expires_at: datetime


def hash_email_verification_token(raw_token: str) -> str:
    """Return the SHA-256 digest persisted for a raw token."""
    if not raw_token:
        raise ValueError("Verification token must not be empty")
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_email_verification_token(
    *,
    now: datetime | None = None,
) -> GeneratedEmailVerificationToken:
    """Generate a 256-bit token that expires after 24 hours."""
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("Token generation requires a timezone-aware timestamp")

    raw_token = secrets.token_urlsafe(EMAIL_VERIFICATION_TOKEN_BYTES)
    return GeneratedEmailVerificationToken(
        raw_token=raw_token,
        token_hash=hash_email_verification_token(raw_token),
        expires_at=issued_at + EMAIL_VERIFICATION_TOKEN_TTL,
    )
