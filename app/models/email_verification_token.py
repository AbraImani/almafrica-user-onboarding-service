"""Email verification token persistence model."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EmailVerificationToken(Base):
    """Single-use, expiring verification token stored only as a hash."""

    __tablename__ = "email_verification_tokens"
    __table_args__ = (
        CheckConstraint(
            "length(token_hash) = 64",
            name="ck_email_verification_tokens_hash_length",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_email_verification_tokens_expiry_after_creation",
        ),
        CheckConstraint(
            "used_at IS NULL OR used_at >= created_at",
            name="ck_email_verification_tokens_use_after_creation",
        ),
        Index(
            "ux_email_verification_tokens_token_hash",
            "token_hash",
            unique=True,
        ),
        Index("ix_email_verification_tokens_user_id", "user_id"),
        Index("ix_email_verification_tokens_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    user_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_email_verification_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
