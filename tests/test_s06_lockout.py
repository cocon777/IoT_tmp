"""Unit and API tests for S6 temporary account lockout and per-IP rate limiting."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User
from app.security import lockout as lockout_module
from app.security.auth import hash_password
from app.security.lockout import reset_rate_limiter


@pytest.fixture(autouse=True)
def _clear_rate_limiter() -> None:
    """Reset IP rate limiter state before each test."""
    reset_rate_limiter()


def _create_user(
    db: Session,
    email: str = "operator@wms.io",
    password: str = "CorrectPass123",
) -> User:
    user = User(
        email=email,
        password_hash=hash_password(password),
        full_name="Operator Lockout Test",
        role="operator",
        status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_five_failed_logins_lock_account_and_unlock_after_expiry(
    db_session: Session,
    override_get_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """5 consecutive wrong passwords lock the account; 6th attempt with right password fails;
    after locked_until passes, login succeeds and resets failed_attempts.
    """
    user = _create_user(db_session)
    client = TestClient(app)

    base_time = datetime(2026, 10, 27, 9, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(lockout_module, "utcnow", lambda: base_time)

    # 1..5 consecutive wrong attempts -> 401
    for i in range(1, 6):
        res = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": f"WrongPass_{i}"},
        )
        assert res.status_code == 401
        db_session.refresh(user)
        assert user.failed_attempts == i

    assert user.locked_until is not None

    # 6th attempt WITH CORRECT PASSWORD inside lockout window -> rejected (403)
    res_sixth = client.post(
        "/api/auth/login",
        json={"email": user.email, "password": "CorrectPass123"},
    )
    assert res_sixth.status_code == 403
    assert "temporarily locked" in res_sixth.json()["detail"].lower()

    # Advance clock by 16 minutes (> 15-minute lockout window)
    future_time = base_time + timedelta(minutes=16)
    monkeypatch.setattr(lockout_module, "utcnow", lambda: future_time)

    # Login with correct password now succeeds and resets failed_attempts & locked_until
    res_unlocked = client.post(
        "/api/auth/login",
        json={"email": user.email, "password": "CorrectPass123"},
    )
    assert res_unlocked.status_code == 200
    assert "access_token" in res_unlocked.json()

    db_session.refresh(user)
    assert user.failed_attempts == 0
    assert user.locked_until is None


def test_ip_rate_limiting_blocks_excessive_requests(
    db_session: Session,
    override_get_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exceeding RATE_LIMIT_MAX_REQUESTS from the same IP returns 429 Too Many Requests."""
    _create_user(db_session)
    monkeypatch.setattr(lockout_module, "RATE_LIMIT_MAX_REQUESTS", 5)
    client = TestClient(app)

    for _ in range(5):
        r = client.post(
            "/api/auth/login",
            headers={"X-Forwarded-For": "203.0.113.50"},
            json={"email": "unknown@wms.io", "password": " any "},
        )
        assert r.status_code == 401

    r_blocked = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "203.0.113.50"},
        json={"email": "unknown@wms.io", "password": " any "},
    )
    assert r_blocked.status_code == 429
    assert "Retry-After" in r_blocked.headers
