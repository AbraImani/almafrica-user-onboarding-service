"""Password security helpers."""

from argon2 import PasswordHasher

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2id."""
    return _password_hasher.hash(password)
