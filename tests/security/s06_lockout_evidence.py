"""Generate evidence file docs/evidence/s6-lockout.txt for security test S6."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
from app.models.user import User  # noqa: E402
from app.security import lockout as lockout_module  # noqa: E402
from app.security.auth import hash_password  # noqa: E402


def main() -> None:
    """Run S6 lockout verification and write docs/evidence/s6-lockout.txt."""
    evidence_path = ROOT_DIR / "docs" / "evidence" / "s6-lockout.txt"
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
    lockout_module.reset_rate_limiter()

    lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    try:
        user = User(
            email="operator_a@wms.io",
            password_hash=hash_password("ValidPass123"),
            full_name="Operator Khu A",
            role="operator",
            status="active",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        t0 = datetime(2026, 10, 27, 9, 15, 0, tzinfo=timezone.utc)
        lockout_module.utcnow = lambda: t0
        client = TestClient(app)

        log("=== KIEM THU BAO MAT S6 (BUOC S6): KHOA TAM SAU 5 LAN DANG NHAP SAI ===")
        log(f"Tai khoan thu nghiem: {user.email}")
        log(f"Thoi diem bat dau (t0): {t0.isoformat()}")
        log("-----------------------------------------------------------------------")

        for attempt in range(1, 6):
            res = client.post(
                "/api/auth/login",
                json={"email": user.email, "password": f"WrongPass#{attempt}"},
            )
            db.refresh(user)
            log(
                f"[Lan {attempt}] Nhap sai mat khau -> HTTP {res.status_code} | "
                f"failed_attempts={user.failed_attempts} | locked_until={user.locked_until}"
            )
            assert res.status_code == 401

        assert user.failed_attempts == 5
        assert user.locked_until is not None

        res6 = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "ValidPass123"},
        )
        db.refresh(user)
        log(
            f"[Lan 6 - Trong thoi gian khoa] Nhap DUNG mat khau -> HTTP {res6.status_code} | "
            f"Body: {res6.json()}"
        )
        assert res6.status_code == 403

        t_after = t0 + timedelta(minutes=16)
        lockout_module.utcnow = lambda: t_after
        log(f"--- Tua dong ho sang t0 + 16 phut ({t_after.isoformat()}) ---")

        res7 = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "ValidPass123"},
        )
        db.refresh(user)
        log(
            f"[Lan 7 - Sau khi het han locked_until] Nhap DUNG mat khau -> HTTP {res7.status_code} | "
            f"failed_attempts={user.failed_attempts} | locked_until={user.locked_until}"
        )
        assert res7.status_code == 200
        assert user.failed_attempts == 0
        assert user.locked_until is None

        log("-----------------------------------------------------------------------")
        log("KET QUA S6: PASS (Khoa tam 15 phut sau 5 lan sai, tu choi lan 6 du dung mat khau, mo khoa sau khi het han)")
        evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        app.dependency_overrides.pop(get_db, None)
        db.close()


if __name__ == "__main__":
    main()
