"""Focused tests for the User persistence model."""

from sqlalchemy import CheckConstraint
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID

from app.core.database import Base
from app.models.user import User, UserRole, normalize_email


def test_user_table_is_registered_with_expected_columns() -> None:
    table = Base.metadata.tables["users"]

    assert list(table.columns.keys()) == [
        "id",
        "full_name",
        "email",
        "password_hash",
        "role",
        "is_verified",
        "profile_image_key",
        "created_at",
        "updated_at",
    ]
    assert isinstance(table.c.id.type, PostgreSQLUUID)
    assert table.c.id.primary_key is True
    assert table.c.created_at.type.timezone is True
    assert table.c.updated_at.type.timezone is True


def test_user_table_has_named_constraints_and_unique_email_index() -> None:
    table = User.__table__
    check_constraint_names = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    email_index = next(index for index in table.indexes if index.name == "ux_users_email")

    assert check_constraint_names == {
        "ck_users_email_normalized",
        "ck_users_full_name_not_blank",
        "ck_users_password_hash_not_blank",
        "ck_users_profile_image_key_not_blank",
    }
    assert email_index.unique is True
    assert [column.name for column in email_index.columns] == ["email"]


def test_email_is_normalized_on_assignment() -> None:
    user = User(
        full_name="Ada Lovelace",
        email="  Ada.Lovelace@Example.COM  ",
        password_hash="stored-hash",
    )

    assert user.email == "ada.lovelace@example.com"
    assert normalize_email("  USER@Example.COM ") == "user@example.com"


def test_supported_user_roles_are_explicit() -> None:
    assert list(UserRole) == [UserRole.USER, UserRole.ADMIN]
