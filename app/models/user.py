"""User persistence model."""

from datetime import datetime
from enum import Enum as PythonEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Index,
    String,
    false,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.database import Base


class UserRole(str, PythonEnum):
    """Roles supported by the application."""

    USER = "USER"
    ADMIN = "ADMIN"


def normalize_email(email: str) -> str:
    """Return the canonical form used for persisted email addresses."""
    normalized_email = email.strip().lower()
    if not normalized_email:
        raise ValueError("Email must not be blank")
    return normalized_email


class User(Base):
    """Persisted user account data."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "length(btrim(full_name)) > 0",
            name="ck_users_full_name_not_blank",
        ),
        CheckConstraint(
            "length(email) > 0 AND email = lower(btrim(email))",
            name="ck_users_email_normalized",
        ),
        CheckConstraint(
            "length(btrim(password_hash)) > 0",
            name="ck_users_password_hash_not_blank",
        ),
        CheckConstraint(
            "profile_image_key IS NULL OR length(btrim(profile_image_key)) > 0",
            name="ck_users_profile_image_key_not_blank",
        ),
        Index("ux_users_email", "email", unique=True),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=True, validate_strings=True),
        nullable=False,
        default=UserRole.USER,
        server_default=UserRole.USER.value,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    profile_image_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    @validates("email")
    def normalize_persisted_email(self, _: str, value: str) -> str:
        """Normalize email assignments before SQLAlchemy persists them."""
        return normalize_email(value)
