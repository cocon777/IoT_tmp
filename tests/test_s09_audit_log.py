"""Unit and API tests for S9 Audit Log service and GET /api/audit-logs."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models import DeviceStub, User
from app.security.auth import create_access_token, hash_password
from app.services import audit


def test_audit_log_records_security_events_and_filters_properly(
    db_session: Session, override_get_db: None
) -> None:
    """Verify audit trail across login, lockout, password change, user CRUD, device assign, and 403/404."""
    dev1 = DeviceStub(id=1, device_code="wms-001", name="Tank A", state="Active")
    admin = User(
        email="admin@wms.io",
        password_hash=hash_password("AdminPass123"),
        full_name="Admin User",
        role="admin",
        status="active",
    )
    db_session.add_all([dev1, admin])
    db_session.commit()

    client = TestClient(app)
    ip_headers = {"X-Forwarded-For": "198.51.100.42"}

    # 1. Login failure & login success
    client.post(
        "/api/auth/login",
        headers=ip_headers,
        json={"email": "admin@wms.io", "password": "BadPassword"},
    )
    r_login = client.post(
        "/api/auth/login",
        headers=ip_headers,
        json={"email": "admin@wms.io", "password": "AdminPass123"},
    )
    assert r_login.status_code == 200
    admin_token = r_login.json()["access_token"]
    admin_headers = {
        "Authorization": f"Bearer {admin_token}",
        "X-Forwarded-For": "198.51.100.42",
    }

    # 2. Admin creates Operator user
    r_create = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": "op_audit@wms.io",
            "password": "OpPassword123",
            "full_name": "Operator Audit",
            "role": "operator",
        },
    )
    assert r_create.status_code == 201
    op_id = r_create.json()["id"]

    # 3. Admin assigns device 1, changes role to viewer, then locks user
    assert (
        client.post(
            f"/api/users/{op_id}/devices/1", headers=admin_headers
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/users/{op_id}",
            headers=admin_headers,
            json={"role": "viewer"},
        ).status_code
        == 200
    )

    # 4. Viewer tries calling /api/audit-logs -> 403 (and logs PERMISSION_DENIED)
    viewer_token = create_access_token(op_id, "viewer")
    r_denied = client.get(
        "/api/audit-logs",
        headers={
            "Authorization": f"Bearer {viewer_token}",
            "X-Forwarded-For": "198.51.100.99",
        },
    )
    assert r_denied.status_code == 403

    # 5. Admin locks user and changes own password
    assert (
        client.patch(
            f"/api/users/{op_id}",
            headers=admin_headers,
            json={"status": "locked"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/auth/change-password",
            headers=admin_headers,
            json={
                "old_password": "AdminPass123",
                "new_password": "NewAdminPass456",
            },
        ).status_code
        == 200
    )

    # 6. Admin queries /api/audit-logs with pagination and user filter
    r_logs = client.get(
        "/api/audit-logs?page=1&page_size=50", headers=admin_headers
    )
    assert r_logs.status_code == 200
    page_data = r_logs.json()
    actions = [item["action"] for item in page_data["items"]]

    for expected_action in (
        "LOGIN_FAILED",
        "LOGIN_SUCCESS",
        "CREATE_USER",
        "ASSIGN_DEVICE",
        "CHANGE_USER_ROLE",
        "PERMISSION_DENIED",
        "LOCK_USER",
        "CHANGE_PASSWORD",
    ):
        assert expected_action in actions, f"Missing audit action: {expected_action}"

    # Verify IP was captured accurately
    ips = {item["ip"] for item in page_data["items"]}
    assert "198.51.100.42" in ips
    assert "198.51.100.99" in ips

    # Filter by user_id (Viewer op_id who triggered PERMISSION_DENIED)
    r_filtered = client.get(
        f"/api/audit-logs?user_id={op_id}", headers=admin_headers
    )
    assert r_filtered.status_code == 200
    assert r_filtered.json()["total"] == 1
    assert r_filtered.json()["items"][0]["action"] == "PERMISSION_DENIED"


def test_audit_log_redacts_sensitive_fields_in_detail(
    db_session: Session,
) -> None:
    """Verify audit.log never stores raw passwords or tokens in detail."""
    entry = audit.log(
        db=db_session,
        user=None,
        action="TEST_REDACT",
        target_type="user",
        target_id="1",
        ip="127.0.0.1",
        detail={"username": "alice", "password": "SuperSecretPassword", "access_token": "jwt123"},
    )
    assert entry.detail is not None
    assert "SuperSecretPassword" not in entry.detail
    assert "jwt123" not in entry.detail
    assert "[REDACTED]" in entry.detail
