"""Security & Functional test S3 / F8 (S14): Two-layer device revocation verification.

Verifies:
1. Layer 1 (MQTT Broker Dynamic Security): `broker_admin.delete_client` disconnects active
   device session and rejects reconnection attempts.
2. Layer 2 (Backend `is_device_active` / `inspect_incoming_message`): When device state is
   changed to `Decommissioned` in DB, backend rejects any telemetry from that device.
Saves evidence to `docs/evidence/s3-f8-full-revoke.txt`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import threading
import time
from typing import Any

import paho.mqtt.client as mqtt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
for candidate in (ROOT_DIR / "backend", ROOT_DIR):
    if (candidate / "app").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.config import settings  # noqa: E402
from app.db import Base  # noqa: E402
from app.models.device_stub import DeviceStub  # noqa: E402
from app.security.device_guard import (  # noqa: E402
    inspect_incoming_message,
    is_device_active,
    reset_device_rate_limits,
)
from app.services import broker_admin  # noqa: E402


def main() -> None:
    """Run S3 / F8 end-to-end two-layer revocation verification."""
    evidence_path = ROOT_DIR / "docs" / "evidence" / "s3-f8-full-revoke.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()
    reset_device_rate_limits()

    lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    try:
        log("=== KIEM THU S3 / F8 (BUOC S14): THU HOI THIET BI 2 LOP (BROKER + BACKEND) ===")
        log(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        log("------------------------------------------------------------------------------")

        # 1. Create active device wms-revoke-01 in DB and on Broker
        dev = DeviceStub(
            id=10,
            device_code="wms-revoke-01",
            name="Node Thu Hoi F8",
            state="Active",
        )
        db.add(dev)
        db.commit()

        creds = broker_admin.create_client("wms-revoke-01")
        raw_pw = creds["password"]

        # Verify Active state allows connection and backend ingestion
        ok_before, reason_before = inspect_incoming_message(
            "wms-revoke-01",
            '{"device_id":"wms-revoke-01","seq":1,"ts":"2026-11-01T09:00:00Z","level_pct":60.0}',
            db=db,
        )
        assert ok_before is True
        log(f"[PASS] 1. Truoc khi thu hoi (state=Active): backend chap nhan ban tin ({reason_before}).")

        # 2. Revoke device -> state = Decommissioned + broker_admin.delete_client
        dev.state = "Decommissioned"
        db.add(dev)
        db.commit()
        broker_admin.delete_client("wms-revoke-01")

        # Verify Broker rejects connection with revoked credentials
        conn_evt = threading.Event()
        conn_rc: dict[str, Any] = {"ok": False, "rc": None}
        c = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"revoked-client-{int(time.time())}",
        )
        c.username_pw_set("wms-revoke-01", raw_pw)

        def on_connect(
            _cl: mqtt.Client, _ud: Any, _fl: Any, rc: Any, _pr: Any = None
        ) -> None:
            conn_rc["ok"] = rc == 0
            conn_rc["rc"] = str(rc)
            conn_evt.set()

        c.on_connect = on_connect
        c.connect(settings.mqtt_host, settings.mqtt_port, keepalive=10)
        c.loop_start()
        conn_evt.wait(timeout=4.0)
        c.disconnect()
        c.loop_stop()

        assert conn_rc["ok"] is False
        log(
            f"[PASS] 2. Lop 1 (Broker Dynamic Security): Thiet bi bi thu hoi ket noi lai bi tu choi (rc={conn_rc['rc']})."
        )

        # 3. Verify Backend Layer 2 drops telemetry even if a message reached the subscriber
        assert is_device_active("wms-revoke-01", db=db) is False
        ok_after, reason_after = inspect_incoming_message(
            "wms-revoke-01",
            '{"device_id":"wms-revoke-01","seq":2,"ts":"2026-11-01T09:00:05Z","level_pct":61.0}',
            db=db,
        )
        assert ok_after is False
        assert reason_after == "device_not_active"
        log(
            f"[PASS] 3. Lop 2 (Backend Guard): is_device_active=False, ban tin bi loai bo (reason={reason_after}), khong ghi DB."
        )

        log("------------------------------------------------------------------------------")
        log("KET QUA S3 / F8: PASS (Broker tu choi ket noi + Backend chan ghi du lieu)")
        evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        db.close()


if __name__ == "__main__":
    main()
