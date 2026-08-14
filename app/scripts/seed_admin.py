"""Create the initial administrator from environment variables."""

import sys

from argon2 import PasswordHasher
from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.core.database import SessionLocal
from app.models.user import User, UserRole, normalize_email


class AdminSeedSettings(BaseSettings):
    """Administrator values required only by the seed command."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    admin_full_name: str = Field(min_length=1, max_length=255)
    admin_email: str = Field(min_length=1, max_length=320)
    admin_password: SecretStr = Field(min_length=12)

    @field_validator("admin_full_name")
    @classmethod
    def strip_full_name(cls, value: str) -> str:
        """Reject a blank name and persist its trimmed form."""
        stripped_value = value.strip()
        if not stripped_value:
            raise ValueError("Administrator full name must not be blank")
        return stripped_value

    @field_validator("admin_email")
    @classmethod
    def normalize_admin_email(cls, value: str) -> str:
        """Use the same canonical email form as the User model."""
        return normalize_email(value)


def seed_administrator(settings: AdminSeedSettings) -> int:
    """Create one verified administrator unless its email already exists."""
    with SessionLocal() as session:
        try:
            existing_user = session.scalar(
                select(User).where(User.email == settings.admin_email)
            )
            if existing_user is not None:
                if existing_user.role == UserRole.ADMIN:
                    print(
                        f"Administrator already exists: {settings.admin_email}. "
                        "No changes made."
                    )
                else:
                    print(
                        f"A user already exists with email {settings.admin_email}. "
                        "No changes made."
                    )
                return 0

            password_hash = PasswordHasher().hash(
                settings.admin_password.get_secret_value()
            )
            administrator = User(
                full_name=settings.admin_full_name,
                email=settings.admin_email,
                password_hash=password_hash,
                role=UserRole.ADMIN,
                is_verified=True,
            )
            session.add(administrator)

            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                concurrent_user = session.scalar(
                    select(User).where(User.email == settings.admin_email)
                )
                if concurrent_user is None:
                    raise
                print(
                    f"A user already exists with email {settings.admin_email}. "
                    "No changes made."
                )
                return 0
        except SQLAlchemyError:
            session.rollback()
            print("Unable to seed the administrator due to a database error.", file=sys.stderr)
            return 1

    print(f"Administrator created: {settings.admin_email}")
    return 0


def main() -> int:
    """Load environment values and run the administrator seed."""
    try:
        settings = AdminSeedSettings()
    except ValidationError:
        print(
            "Invalid administrator seed configuration. Set ADMIN_FULL_NAME, "
            "ADMIN_EMAIL, and ADMIN_PASSWORD (minimum 12 characters).",
            file=sys.stderr,
        )
        return 1

    return seed_administrator(settings)


if __name__ == "__main__":
    raise SystemExit(main())
