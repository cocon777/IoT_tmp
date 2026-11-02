"""Unit and API tests for S5 authentication, JWT, and password management."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User
from app.security.auth import create_access_token, hash_password


def _seed_user(
    db: Session,
    email: str = "admin@wms.io",
    password: str = "StrongPass123",
    role: str = "admin",
    status: str = "active",
) -> User:
    user = User(
        email=email,
        password_hash=hash_password(password),
        full_name="Test Admin",
        role=role,
        status=status,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_login_success_and_no_password_hash(
    db_session: Session, override_get_db: None
) -> None:
    """Valid login returns JWT and user object without exposing password_hash."""
    _seed_user(db_session)
    client = TestClient(app)

    res = client.post(
        "/api/auth/login",
        json={"email": "admin@wms.io", "password": "StrongPass123"},
    )
    assert res.status_code == 200
    body = res.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    assert "password_hash" not in body
    assert "password_hash" not in body["user"]
    assert body["user"]["email"] == "admin@wms.io"
    assert body["user"]["role"] == "admin"


def test_login_generic_error_on_wrong_password_or_unknown_email(
    db_session: Session, override_get_db: None
) -> None:
    """Wrong password and unknown email must return the exact same 401 detail."""
    _seed_user(db_session)
    client = TestClient(app)

    res_wrong_pw = client.post(
        "/api/auth/login",
        json={"email": "admin@wms.io", "password": "WrongPassword999"},
    )
    res_unknown_email = client.post(
        "/api/auth/login",
        json={"email": "nonexistent@wms.io", "password": "WrongPassword999"},
    )

    assert res_wrong_pw.status_code == 401
    assert res_unknown_email.status_code == 401
    assert res_wrong_pw.json()["detail"] == res_unknown_email.json()["detail"]


def test_login_rejected_when_user_status_locked(
    db_session: Session, override_get_db: None
) -> None:
    """Disabled/locked account cannot log in even with valid password."""
    _seed_user(db_session, email="locked@wms.io", status="locked")
    client = TestClient(app)

    res = client.post(
        "/api/auth/login",
        json={"email": "locked@wms.io", "password": "StrongPass123"},
    )
    assert res.status_code == 403


def test_s2_missing_invalid_and_expired_token_return_401(
    db_session: Session, override_get_db: None
) -> None:
    """Missing token, tampered token, and expired token all return 401 (S2)."""
    user = _seed_user(db_session)
    client = TestClient(app)

    # 1. No token
    r_missing = client.get("/api/me")
    assert r_missing.status_code == 401

    # 2. Invalid signature / malformed token
    r_invalid = client.get(
        "/api/me",
        headers={"Authorization": "Bearer invalid.jwt.token.value"},
    )
    assert r_invalid.status_code == 401

    # 3. Expired token
    expired_token = create_access_token(
        user_id=user.id,
        role=user.role,
        expires_delta=timedelta(seconds=-10),
    )
    r_expired = client.get(
        "/api/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert r_expired.status_code == 401


def test_change_password_and_logout(
    db_session: Session, override_get_db: None
) -> None:
    """Verify change-password complexity check and logout token revocation."""
    user = _seed_user(db_session)
    client = TestClient(app)
    token = create_access_token(user_id=user.id, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    # Weak new password -> 422
    r_weak = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"old_password": "StrongPass123", "new_password": "weak"},
    )
    assert r_weak.status_code == 422

    # Wrong old password -> 401
    r_wrong_old = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"old_password": "WrongOld123", "new_password": "NewStrongPass456"},
    )
    assert r_wrong_old.status_code == 401

    # Valid password change -> 200
    r_ok = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"old_password": "StrongPass123", "new_password": "NewStrongPass456"},
    )
    assert r_ok.status_code == 200

    # Logout -> revokes token
    r_logout = client.post("/api/auth/logout", headers=headers)
    assert r_logout.status_code == 200

    # Re-using logged-out token -> 401
    r_after = client.get("/api/me", headers=headers)
    assert r_after.status_code == 401
