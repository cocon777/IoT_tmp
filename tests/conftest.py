"""Pytest configuration and shared fixtures using in-memory SQLite."""

from __future__ import annotations

from collections.abc import Generator
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

ROOT_DIR = Path(__file__).resolve().parent.parent
for candidate in (ROOT_DIR / "backend", ROOT_DIR):
    if (candidate / "app").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.db import Base, get_db  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
import app.models  # noqa: F401, E402


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Provide an isolated in-memory SQLite session for unit tests."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )
    session = TestingSessionLocal()
    import app.db

    old_session_local = app.db.SessionLocal
    app.db.SessionLocal = TestingSessionLocal
    try:
        yield session
    finally:
        app.db.SessionLocal = old_session_local
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture()
def override_get_db(db_session: Session) -> Generator[None, None, None]:
    """Override FastAPI get_db dependency with the in-memory SQLite session."""

    def _get_test_db() -> Generator[Session, None, None]:
        yield db_session

    fastapi_app.dependency_overrides[get_db] = _get_test_db
    try:
        yield
    finally:
        fastapi_app.dependency_overrides.pop(get_db, None)
