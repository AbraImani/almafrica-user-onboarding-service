"""Schemas for authentication-related operations."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
)

from app.models.user import UserRole, normalize_email


def validate_password_policy(password: SecretStr) -> SecretStr:
    """Apply the password policy shared by registration and password changes."""
    plaintext = password.get_secret_value()
    if not any(character.isalpha() for character in plaintext):
        raise ValueError("Password must contain at least one letter")
    if not any(character.isdigit() for character in plaintext):
        raise ValueError("Password must contain at least one number")
    return password


class UserRegistrationRequest(BaseModel):
    """Validated public registration input."""

    full_name: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=2, max_length=255),
    ]
    email: Annotated[EmailStr, Field(max_length=320)]
    password: SecretStr = Field(min_length=12, max_length=128)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        """Reject names without any alphabetic character."""
        if not any(character.isalpha() for character in value):
            raise ValueError("Full name must contain at least one letter")
        return value

    @field_validator("email", mode="before")
    @classmethod
    def normalize_registration_email(cls, value: object) -> object:
        """Normalize strings before validating their email format."""
        if isinstance(value, str):
            return normalize_email(value)
        return value

    @field_validator("password")
    @classmethod
    def validate_password_policy(cls, value: SecretStr) -> SecretStr:
        """Require a practical minimum mix of letters and numbers."""
        return validate_password_policy(value)


class UserRegistrationResponse(BaseModel):
    """Safe user data returned after registration."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    full_name: str
    email: EmailStr
    role: UserRole
    is_verified: bool
    created_at: datetime


class EmailVerificationRequest(BaseModel):
    """Raw verification token delivered through the user's email."""

    token: SecretStr = Field(min_length=1, max_length=512)


class EmailVerificationResponse(BaseModel):
    """Public result returned after an email is verified."""

    message: str
    is_verified: bool


class UserLoginRequest(BaseModel):
    """Credentials accepted by the login endpoint."""

    email: Annotated[EmailStr, Field(max_length=320)]
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_login_email(cls, value: object) -> object:
        """Normalize login email exactly like registration email."""
        if isinstance(value, str):
            return normalize_email(value)
        return value


class AccessTokenResponse(BaseModel):
    """Bearer access token returned after successful authentication."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginResponse(AccessTokenResponse):
    """Access and refresh credentials created by a successful login."""

    refresh_token: str
    refresh_expires_in: int


class RefreshTokenRequest(BaseModel):
    """Opaque refresh token used to obtain a new access token."""

    refresh_token: SecretStr = Field(min_length=1, max_length=512)


class LogoutResponse(BaseModel):
    """Idempotent result returned after ending a refresh session."""

    message: str


class CurrentUserResponse(BaseModel):
    """Safe representation returned for the authenticated user."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    full_name: str
    email: EmailStr
    role: UserRole
    is_verified: bool
    profile_image_key: str | None
    created_at: datetime
    updated_at: datetime


class UserProfileUpdateRequest(BaseModel):
    """Strict self-profile fields a user is allowed to change."""

    model_config = ConfigDict(extra="forbid")

    full_name: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=2, max_length=255),
    ]

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        """Reject names without any alphabetic character."""
        if not any(character.isalpha() for character in value):
            raise ValueError("Full name must contain at least one letter")
        return value


class PasswordChangeRequest(BaseModel):
    """Secrets required to change the authenticated user's password."""

    model_config = ConfigDict(extra="forbid")

    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password_policy(cls, value: SecretStr) -> SecretStr:
        """Apply the same practical policy used during registration."""
        return validate_password_policy(value)


class PasswordChangeResponse(BaseModel):
    """Public confirmation returned after a password change."""

    message: str


class ErrorDetail(BaseModel):
    """Stable machine-readable API error details."""

    code: str
    message: str


class ErrorResponse(BaseModel):
    """FastAPI HTTP error response shape."""

    detail: ErrorDetail
