"""Functional test F1 (S14): Log in as 3 roles (Admin, Operator, Viewer) and test every capability.

Saves complete verification report to `docs/evidence/f1-rbac-matrix.txt`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
for candidate in (ROOT_DIR / "backend", ROOT_DIR):
    if (candidate / "app").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.db import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import DeviceStub, User, UserDevice  # noqa: E402
from app.security.auth import hash_password  # noqa: E402
from app.security.lockout import reset_rate_limiter  # noqa: E402


def main() -> None:
    """Execute F1 login + 3-role matrix verification and write docs/evidence/f1-rbac-matrix.txt."""
    evidence_path = ROOT_DIR / "docs" / "evidence" / "f1-rbac-matrix.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()
    app.dependency_overrides[get_db] = lambda: db
    reset_rate_limiter()

    lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    try:
        dev1 = DeviceStub(id=1, device_code="wms-001", name="Bon Khu A", state="Active")
        dev2 = DeviceStub(id=2, device_code="wms-002", name="Bon Khu B", state="Active")
        admin = User(
            email="admin@wms.io",
            password_hash=hash_password("AdminPass123"),
            full_name="Admin User",
            role="admin",
            status="active",
        )
        op_a = User(
            email="operator_a@wms.io",
            password_hash=hash_password("OpPass123"),
            full_name="Operator Khu A",
            role="operator",
            status="active",
        )
        viewer = User(
            email="viewer@wms.io",
            password_hash=hash_password("ViewPass123"),
            full_name="Viewer Khu A",
            role="viewer",
            status="active",
        )
        db.add_all([dev1, dev2, admin, op_a, viewer])
        db.flush()
        db.add_all(
            [
                UserDevice(user_id=op_a.id, device_id=dev1.id),
                UserDevice(user_id=viewer.id, device_id=dev1.id),
            ]
        )
        db.commit()

        client = TestClient(app)
        log("=== KIEM THU CHUC NANG F1 (BUOC S14): DANG NHAP & PHAN QUYEN 3 VAI TRO ===")
        log(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        log("--------------------------------------------------------------------------")

        tokens: dict[str, str] = {}
        for role_label, email, pw in [
            ("admin", "admin@wms.io", "AdminPass123"),
            ("operator", "operator_a@wms.io", "OpPass123"),
            ("viewer", "viewer@wms.io", "ViewPass123"),
        ]:
            r_login = client.post(
                "/api/auth/login", json={"email": email, "password": pw}
            )
            assert r_login.status_code == 200
            tokens[role_label] = r_login.json()["access_token"]
            log(f"[PASS] Dang nhap {role_label} ({email}) -> HTTP 200 (nhan JWT)")

        scenarios = [
            ("1. Quan ly nguoi dung (GET /api/users)", "GET", "/api/users", None, {"admin": 200, "operator": 403, "viewer": 403}),
            ("2. Xem tai khoan ca nhan (GET /api/me)", "GET", "/api/me", None, {"admin": 200, "operator": 200, "viewer": 200}),
            ("3. Dang ky thiet bi (POST /api/devices)", "POST", "/api/devices", {"device_code": "wms-009"}, {"admin": 200, "operator": 403, "viewer": 403}),
            ("4. Gan thiet bi cho user (POST /api/users/2/devices/1)", "POST", f"/api/users/{op_a.id}/devices/1", None, {"admin": 200, "operator": 403, "viewer": 403}),
            ("5. Xem thiet bi duoc gan (GET /api/devices/1)", "GET", "/api/devices/1", None, {"admin": 200, "operator": 200, "viewer": 200}),
            ("6. Xem telemetry thiet bi duoc gan (GET /api/devices/1/telemetry)", "GET", "/api/devices/1/telemetry", None, {"admin": 200, "operator": 200, "viewer": 200}),
            ("7. Xuat CSV thiet bi duoc gan (GET /api/devices/1/telemetry/export)", "GET", "/api/devices/1/telemetry/export", None, {"admin": 200, "operator": 200, "viewer": 403}),
            ("8. Doi cau hinh thiet bi (PUT /api/devices/1/config)", "PUT", "/api/devices/1/config", {"low_pct": 25}, {"admin": 200, "operator": 200, "viewer": 403}),
            ("9. Gui lenh bom (POST /api/devices/1/commands)", "POST", "/api/devices/1/commands", {"action": "pump", "value": "on"}, {"admin": 200, "operator": 200, "viewer": 403}),
            ("10. Chuyen sang Maintenance (PATCH /api/devices/1/maintenance)", "PATCH", "/api/devices/1/maintenance", None, {"admin": 200, "operator": 200, "viewer": 403}),
            ("11. Xem canh bao (GET /api/devices/1/alerts)", "GET", "/api/devices/1/alerts", None, {"admin": 200, "operator": 200, "viewer": 200}),
            ("12. Ack canh bao (POST /api/devices/1/alerts/ack)", "POST", "/api/devices/1/alerts/ack", {}, {"admin": 200, "operator": 200, "viewer": 403}),
            ("13. Xem audit log (GET /api/audit-logs)", "GET", "/api/audit-logs", None, {"admin": 200, "operator": 403, "viewer": 403}),
        ]

        for label, method, path, body, expected_map in scenarios:
            results_str: list[str] = []
            for role_name, expected_code in expected_map.items():
                res = client.request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {tokens[role_name]}"},
                    json=body,
                )
                assert res.status_code == expected_code, (
                    f"{label} [{role_name}]: expected {expected_code}, got {res.status_code}"
                )
                results_str.append(f"{role_name}={res.status_code}")
            log(f"[PASS] {label} -> {', '.join(results_str)}")

        log("--------------------------------------------------------------------------")
        log("KET QUA F1: 13/13 CHUC NANG PASS TREN CA 3 VAI TRO (ADMIN, OPERATOR, VIEWER)")
        evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        app.dependency_overrides.pop(get_db, None)
        db.close()


if __name__ == "__main__":
    main()
