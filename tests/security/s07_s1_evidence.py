"""Generate evidence file docs/evidence/s1-cross-device.txt for security test S1 (S7)."""

from __future__ import annotations

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
from app.security.auth import create_access_token, hash_password  # noqa: E402


def main() -> None:
    """Run S1 cross-device access verification and save docs/evidence/s1-cross-device.txt."""
    evidence_path = ROOT_DIR / "docs" / "evidence" / "s1-cross-device.txt"
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

    lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    try:
        dev_a = DeviceStub(id=1, device_code="wms-001", name="Bon Khu A", state="Active")
        dev_b = DeviceStub(id=2, device_code="wms-002", name="Bon Khu B", state="Active")
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
        viewer = User(
            email="viewer@wms.io",
            password_hash=hash_password("Pass1234"),
            full_name="Viewer A",
            role="viewer",
            status="active",
        )
        db.add_all([dev_a, dev_b, op_a, op_b, viewer])
        db.flush()
        db.add_all(
            [
                UserDevice(user_id=op_a.id, device_id=dev_a.id),
                UserDevice(user_id=viewer.id, device_id=dev_a.id),
                UserDevice(user_id=op_b.id, device_id=dev_b.id),
            ]
        )
        db.commit()

        token_op_a = create_access_token(op_a.id, op_a.role)
        token_viewer = create_access_token(viewer.id, viewer.role)
        client = TestClient(app)

        log("=== KIEM THU BAO MAT S1 (BUOC S7): KIEM SOAT PHAM VI THIET BI & RBAC ===")
        log("Cau hinh pham vi: Operator A -> wms-001 (id=1); Operator B -> wms-002 (id=2)")
        log("------------------------------------------------------------------------")

        # 1. Operator A goi thiet bi cua minh (id=1) -> 200
        r_own = client.post(
            "/api/devices/1/commands",
            headers={"Authorization": f"Bearer {token_op_a}"},
            json={"action": "pump", "value": "on"},
        )
        log(f"[1] Operator A gui lenh bom tren thiet bi duoc gan (id=1): HTTP {r_own.status_code} | {r_own.json()}")
        assert r_own.status_code == 200

        # 2. Operator A xem/dieu khien thiet bi cua Operator B (id=2) -> 404
        for method, path, payload in [
            ("GET", "/api/devices/2", None),
            ("GET", "/api/devices/2/telemetry", None),
            ("POST", "/api/devices/2/commands", {"action": "pump", "value": "on"}),
            ("PUT", "/api/devices/2/config", {"low_pct": 25}),
        ]:
            r_cross = client.request(
                method,
                path,
                headers={"Authorization": f"Bearer {token_op_a}"},
                json=payload,
            )
            log(f"[2] Operator A goi {method} {path} (thiet bi cua B): HTTP {r_cross.status_code} | {r_cross.json()}")
            assert r_cross.status_code == 404

        # 3. Viewer goi lenh bom tren thiet bi duoc gan (id=1) -> 403
        r_viewer_cmd = client.post(
            "/api/devices/1/commands",
            headers={"Authorization": f"Bearer {token_viewer}"},
            json={"action": "pump", "value": "on"},
        )
        log(f"[3] Viewer gui lenh bom tren thiet bi id=1: HTTP {r_viewer_cmd.status_code} | {r_viewer_cmd.json()}")
        assert r_viewer_cmd.status_code == 403

        log("------------------------------------------------------------------------")
        log("KET QUA S1: PASS (Operator A bi chan 404 khi truy cap thiet bi cua B; Viewer bi chan 403 khi dieu khien)")
        evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        app.dependency_overrides.pop(get_db, None)
        db.close()


if __name__ == "__main__":
    main()
