"""SQLAlchemy engine and session configuration."""

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

engine = create_engine(
    settings.sqlalchemy_database_url,
    connect_args={"connect_timeout": settings.database_connect_timeout_seconds},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    expire_on_commit=False,
)


def get_database_session() -> Generator[Session, None, None]:
    """Provide a database session and always close it after use."""
    with SessionLocal() as session:
        yield session


def database_is_reachable() -> bool:
    """Return whether PostgreSQL accepts a simple query."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False

    return True
