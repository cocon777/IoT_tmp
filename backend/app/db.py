"""Database engine, session factory, helpers, and FastAPI dependency (TV2 + TV3)."""

from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    """Declarative base class for all SQLAlchemy ORM models."""


connect_args = (
    {"check_same_thread": False, "timeout": 15}
    if settings.effective_database_url.startswith("sqlite")
    else {"init_command": "SET time_zone='+00:00'"}
    if settings.effective_database_url.startswith("mysql")
    else {}
)

engine = create_engine(
    settings.effective_database_url,
    pool_pre_ping=True,
    pool_recycle=1800,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    bind=engine,
)


def utcnow() -> datetime:
    """Return current UTC datetime (naive UTC for SQLAlchemy DateTime columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy database session per request and close on exit.

    Yields:
        Session: Active SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
