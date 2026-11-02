"""Unit and API tests for S7 RBAC permission matrix and device-scope enforcement."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app.main import app
from app.models import DeviceStub, User, UserDevice
from app.security.auth import create_access_token, hash_password
from app.security.rbac import PERMISSION_MATRIX, can_access_device


@pytest.fixture()
def rbac_world(db_session: Session) -> dict[str, object]:
    """Create 3 roles (Admin, Operator A, Operator B, Viewer) and 2 devices."""
    dev1 = DeviceStub(id=1, device_code="wms-001", name="Tank A", state="Active")
    dev2 = DeviceStub(id=2, device_code="wms-002", name="Tank B", state="Active")
    db_session.add_all([dev1, dev2])
    db_session.flush()

    admin = User(
        email="admin@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Admin User",
        role="admin",
        status="active",
    )
    op_a = User(
        email="operator_a@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Operator A",
        role="operator",
        status="active",
    )
    op_b = User(
        email="operator_b@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Operator B",
        role="operator",
        status="active",
    )
    viewer_a = User(
        email="viewer_a@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Viewer A",
        role="viewer",
        status="active",
    )
    db_session.add_all([admin, op_a, op_b, viewer_a])
    db_session.flush()

    # Assign Operator A & Viewer A -> dev1; Operator B -> dev2
    db_session.add_all(
        [
            UserDevice(user_id=op_a.id, device_id=dev1.id),
            UserDevice(user_id=viewer_a.id, device_id=dev1.id),
            UserDevice(user_id=op_b.id, device_id=dev2.id),
        ]
    )
    db_session.commit()

    return {
        "dev1": dev1,
        "dev2": dev2,
        "admin": admin,
        "op_a": op_a,
        "op_b": op_b,
        "viewer_a": viewer_a,
        "tokens": {
            "admin": create_access_token(admin.id, admin.role),
            "op_a": create_access_token(op_a.id, op_a.role),
            "op_b": create_access_token(op_b.id, op_b.role),
            "viewer_a": create_access_token(viewer_a.id, viewer_a.role),
        },
    }


def test_permission_matrix_has_all_13_rows() -> None:
    """Ensure PERMISSION_MATRIX defines all 13 actions from section 1.2."""
    expected_actions = {
        "users:manage",
        "account:self",
        "devices:lifecycle_admin",
        "devices:assign",
        "devices:view",
        "telemetry:view",
        "telemetry:export_csv",
        "devices:update_config",
        "devices:send_command",
        "devices:set_maintenance",
        "alerts:view",
        "alerts:ack_close",
        "audit_logs:view",
    }
    assert set(PERMISSION_MATRIX.keys()) == expected_actions


def test_can_access_device_two_arg_signature(
    db_session: Session, rbac_world: dict[str, object]
) -> None:
    """Verify can_access_device(user, device_id) works with 2 arguments."""
    admin: User = rbac_world["admin"]  # type: ignore[assignment]
    op_a: User = rbac_world["op_a"]  # type: ignore[assignment]
    op_b: User = rbac_world["op_b"]  # type: ignore[assignment]
    viewer_a: User = rbac_world["viewer_a"]  # type: ignore[assignment]

    assert can_access_device(admin, 1) is True
    assert can_access_device(admin, 2) is True
    assert can_access_device(op_a, 1) is True
    assert can_access_device(op_a, 2) is False
    assert can_access_device(op_b, 1) is False
    assert can_access_device(op_b, 2) is True
    assert can_access_device(viewer_a, 1) is True
    assert can_access_device(viewer_a, 2) is False


@pytest.mark.parametrize(
    ("method", "path_template", "body", "expected_by_actor"),
    [
        # Lifecycle admin: only Admin (200), Operator/Viewer -> 403
        (
            "POST",
            "/api/devices",
            {"device_code": "wms-009"},
            {"admin": 200, "op_a_dev1": 403, "op_a_dev2": 403, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
        (
            "POST",
            "/api/devices/{dev_id}/provision",
            {},
            {"admin": 200, "op_a_dev1": 403, "op_a_dev2": 403, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
        # View device: Admin (200), Operator/Viewer on assigned (200), on unassigned (404)
        (
            "GET",
            "/api/devices/{dev_id}",
            None,
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 200, "viewer_dev2": 404},
        ),
        # View telemetry: Admin (200), Operator/Viewer on assigned (200), on unassigned (404)
        (
            "GET",
            "/api/devices/{dev_id}/telemetry",
            None,
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 200, "viewer_dev2": 404},
        ),
        # Export CSV: Admin (200), Operator on assigned (200), Operator on unassigned (404), Viewer (403)
        (
            "GET",
            "/api/devices/{dev_id}/telemetry/export",
            None,
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
        # Update config: Admin (200), Operator on assigned (200), Operator on unassigned (404), Viewer (403)
        (
            "PUT",
            "/api/devices/{dev_id}/config",
            {"low_pct": 20, "high_pct": 90},
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
        # Send pump command: Admin (200), Operator on assigned (200), Operator on unassigned (404), Viewer (403)
        (
            "POST",
            "/api/devices/{dev_id}/commands",
            {"action": "pump", "value": "on"},
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
        # Set Maintenance: Admin (200), Operator on assigned (200), Operator on unassigned (404), Viewer (403)
        (
            "PATCH",
            "/api/devices/{dev_id}/maintenance",
            None,
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
        # View alerts: Admin (200), Operator/Viewer on assigned (200), on unassigned (404)
        (
            "GET",
            "/api/devices/{dev_id}/alerts",
            None,
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 200, "viewer_dev2": 404},
        ),
        # Ack/close alerts: Admin (200), Operator on assigned (200), Operator on unassigned (404), Viewer (403)
        (
            "POST",
            "/api/devices/{dev_id}/alerts/ack",
            {},
            {"admin": 200, "op_a_dev1": 200, "op_a_dev2": 404, "viewer_dev1": 403, "viewer_dev2": 403},
        ),
    ],
)
def test_matrix_cells_across_roles_and_devices(
    override_get_db: None,
    rbac_world: dict[str, object],
    method: str,
    path_template: str,
    body: dict[str, object] | None,
    expected_by_actor: dict[str, int],
) -> None:
    """Verify every cell of the permission matrix returns 200, 403, or 404 as specified."""
    client = TestClient(app)
    tokens: dict[str, str] = rbac_world["tokens"]  # type: ignore[assignment]

    cases = [
        ("admin", tokens["admin"], 2),
        ("op_a_dev1", tokens["op_a"], 1),
        ("op_a_dev2", tokens["op_a"], 2),
        ("viewer_dev1", tokens["viewer_a"], 1),
        ("viewer_dev2", tokens["viewer_a"], 2),
    ]

    for actor_key, token, dev_id in cases:
        url = path_template.format(dev_id=dev_id)
        headers = {"Authorization": f"Bearer {token}"}
        res = client.request(method, url, headers=headers, json=body)
        assert res.status_code == expected_by_actor[actor_key], (
            f"Mismatch for {actor_key} on {method} {url}: "
            f"got {res.status_code}, expected {expected_by_actor[actor_key]}"
        )
