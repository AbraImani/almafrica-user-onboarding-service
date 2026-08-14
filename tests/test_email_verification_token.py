"""Tests for email verification token persistence and generation."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import CheckConstraint
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID

from app.core.database import Base
from app.models import EmailVerificationToken
from app.services.email_verification import (
    EMAIL_VERIFICATION_TOKEN_TTL,
    generate_email_verification_token,
    hash_email_verification_token,
)


def test_verification_token_table_metadata() -> None:
    table = Base.metadata.tables["email_verification_tokens"]

    assert list(table.columns.keys()) == [
        "id",
        "user_id",
        "token_hash",
        "expires_at",
        "used_at",
        "created_at",
    ]
    assert isinstance(table.c.id.type, PostgreSQLUUID)
    assert isinstance(table.c.user_id.type, PostgreSQLUUID)
    assert table.c.id.primary_key is True
    assert table.c.expires_at.type.timezone is True
    assert table.c.used_at.type.timezone is True
    assert table.c.created_at.type.timezone is True


def test_verification_token_constraints_and_indexes() -> None:
    table = EmailVerificationToken.__table__
    foreign_key = next(iter(table.c.user_id.foreign_keys))
    check_names = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    indexes = {index.name: index for index in table.indexes}

    assert foreign_key.target_fullname == "users.id"
    assert foreign_key.ondelete == "CASCADE"
    assert check_names == {
        "ck_email_verification_tokens_expiry_after_creation",
        "ck_email_verification_tokens_hash_length",
        "ck_email_verification_tokens_use_after_creation",
    }
    assert indexes["ux_email_verification_tokens_token_hash"].unique is True
    assert indexes["ix_email_verification_tokens_user_id"].unique is False
    assert indexes["ix_email_verification_tokens_expires_at"].unique is False


def test_generated_tokens_are_random_hashed_and_expiring() -> None:
    issued_at = datetime(2026, 8, 14, 10, 0, tzinfo=timezone.utc)

    first = generate_email_verification_token(now=issued_at)
    second = generate_email_verification_token(now=issued_at)

    assert first.raw_token != second.raw_token
    assert first.token_hash != first.raw_token
    assert first.token_hash == hash_email_verification_token(first.raw_token)
    assert len(first.token_hash) == 64
    assert first.expires_at == issued_at + timedelta(hours=24)
    assert first.expires_at.tzinfo is not None
    assert EMAIL_VERIFICATION_TOKEN_TTL == timedelta(hours=24)


def test_token_generation_rejects_naive_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_email_verification_token(now=datetime(2026, 8, 14, 10, 0))
