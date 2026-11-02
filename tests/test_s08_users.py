"""Unit and API tests for S8 User Management & Device Assignment (Admin only)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models import DeviceStub, User
from app.security.auth import create_access_token, hash_password


def _setup_actors(db: Session) -> dict[str, object]:
    dev1 = DeviceStub(id=1, device_code="wms-001", name="Tank A", state="Active")
    admin = User(
        email="admin@wms.io",
        password_hash=hash_password("AdminPass123"),
        full_name="Sole Admin",
        role="admin",
        status="active",
    )
    operator = User(
        email="operator@wms.io",
        password_hash=hash_password("OpPass123"),
        full_name="Operator One",
        role="operator",
        status="active",
    )
    viewer = User(
        email="viewer@wms.io",
        password_hash=hash_password("ViewPass123"),
        full_name="Viewer One",
        role="viewer",
        status="active",
    )
    db.add_all([dev1, admin, operator, viewer])
    db.commit()
    return {
        "dev1": dev1,
        "admin": admin,
        "operator": operator,
        "viewer": viewer,
        "admin_token": create_access_token(admin.id, admin.role),
        "op_token": create_access_token(operator.id, operator.role),
        "viewer_token": create_access_token(viewer.id, viewer.role),
    }


def test_operator_and_viewer_receive_403_on_user_management(
    db_session: Session, override_get_db: None
) -> None:
    """Operator and Viewer cannot list, create, update users, or assign devices."""
    ctx = _setup_actors(db_session)
    client = TestClient(app)

    for token in (ctx["op_token"], ctx["viewer_token"]):
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/users", headers=headers).status_code == 403
        assert (
            client.post(
                "/api/users",
                headers=headers,
                json={
                    "email": "new@wms.io",
                    "password": "StrongPass123",
                    "full_name": "New User",
                    "role": "viewer",
                },
            ).status_code
            == 403
        )
        assert (
            client.patch(
                f"/api/users/{ctx['viewer'].id}",
                headers=headers,
                json={"role": "operator"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"/api/users/{ctx['viewer'].id}/devices/1",
                headers=headers,
            ).status_code
            == 403
        )


def test_admin_crud_assign_device_and_last_admin_protection(
    db_session: Session, override_get_db: None
) -> None:
    """Admin can create, lock, change role, assign/unassign devices, and cannot lock/demote last admin."""
    ctx = _setup_actors(db_session)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {ctx['admin_token']}"}
    admin: User = ctx["admin"]  # type: ignore[assignment]

    # 1. Create new operator
    r_create = client.post(
        "/api/users",
        headers=headers,
        json={
            "email": "op2@wms.io",
            "password": "StrongPass123",
            "full_name": "Operator Two",
            "role": "operator",
        },
    )
    assert r_create.status_code == 201
    new_user = r_create.json()
    assert "password_hash" not in new_user
    new_uid = new_user["id"]

    # 2. Invalid role -> 422
    r_bad_role = client.post(
        "/api/users",
        headers=headers,
        json={
            "email": "bad@wms.io",
            "password": "StrongPass123",
            "full_name": "Bad Role",
            "role": "superadmin",
        },
    )
    assert r_bad_role.status_code == 422

    # 3. Assign & unassign device 1 to new user
    r_assign = client.post(f"/api/users/{new_uid}/devices/1", headers=headers)
    assert r_assign.status_code == 200
    assert r_assign.json()["assigned_device_ids"] == [1]

    r_unassign = client.delete(f"/api/users/{new_uid}/devices/1", headers=headers)
    assert r_unassign.status_code == 200
    assert r_unassign.json()["assigned_device_ids"] == []

    # 4. Change role & lock target user
    r_patch = client.patch(
        f"/api/users/{new_uid}",
        headers=headers,
        json={"role": "viewer", "status": "locked"},
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["role"] == "viewer"
    assert r_patch.json()["status"] == "locked"

    # 5. Last active Admin cannot lock or demote themselves
    r_self_lock = client.patch(
        f"/api/users/{admin.id}",
        headers=headers,
        json={"status": "locked"},
    )
    assert r_self_lock.status_code == 400

    r_self_demote = client.patch(
        f"/api/users/{admin.id}",
        headers=headers,
        json={"role": "operator"},
    )
    assert r_self_demote.status_code == 400
