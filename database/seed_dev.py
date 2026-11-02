"""Seed development database with sample sites, devices, configs, telemetry, users, and assignments.

Integrated TV2 + TV3 dev seed.
Prints randomly generated passwords ONCE to console if not set via environment.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
import os
from pathlib import Path
import secrets
import sys

import bcrypt

# Allow running from repo root or inside container (/app)
ROOT_DIR = Path(__file__).resolve().parent.parent
for candidate in (ROOT_DIR / "backend", ROOT_DIR):
    if (candidate / "app").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.db import Base, SessionLocal, engine, utcnow  # noqa: E402
from app.device_params import DEFAULTS as CONFIG_DEFAULTS  # noqa: E402
from app.models import (  # noqa: E402
    Device,
    DeviceConfig,
    Site,
    Telemetry,
    User,
    UserDevice,
)


def _hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(
        plain_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")


def seed() -> None:
    """Create tables and seed sample sites, devices, configs, telemetry, and accounts."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Seed Site
        site = db.query(Site).filter(Site.name == "Nhà mẫu").first()
        if not site:
            site = Site(name="Nhà mẫu", description="Địa điểm demo")
            db.add(site)
            db.flush()

        # 2. Seed Devices
        devices_spec = [
            ("wms-001", "Bồn nước khu A (Node chính)", "Active", True),
            ("wms-002", "Bồn nước khu B (Giả lập)", "Active", True),
            ("wms-003", "Bồn nước dự phòng", "Registered", False),
        ]
        device_map: dict[str, Device] = {}
        for code, name, state, online in devices_spec:
            dev = db.query(Device).filter(Device.device_code == code).first()
            if not dev:
                dev = Device(
                    device_code=code,
                    name=name,
                    site_id=site.id,
                    state=state,
                    hw_version="v1",
                    fw_version="0.1.0",
                    online=online,
                )
                db.add(dev)
                db.flush()
            device_map[code] = dev

        # 3. Seed default configs for devices
        for dev in device_map.values():
            existing_keys = {
                c.key
                for c in db.query(DeviceConfig.key)
                .filter(DeviceConfig.device_id == dev.id)
                .all()
            }
            new_configs = []
            for k, v in CONFIG_DEFAULTS.items():
                if k not in existing_keys:
                    new_configs.append(
                        DeviceConfig(device_id=dev.id, key=k, value=v, version=1)
                    )
            if new_configs:
                db.add_all(new_configs)
        db.flush()

        # 4. Seed 24h sample telemetry for wms-001 (288 rows, 5-minute intervals)
        wms1 = device_map["wms-001"]
        t_count = db.query(Telemetry).filter(Telemetry.device_id == wms1.id).count()
        if t_count == 0:
            now = utcnow()
            telemetry_rows = []
            for i in range(288):
                sample_time = now - timedelta(minutes=(287 - i) * 5)
                level_pct = round(55.0 + 30.0 * math.sin(i / 30.0), 1)
                distance_cm = round(25.0 * (1.0 - (level_pct / 100.0)), 1)
                pump_on = 1 if (i % 60) in range(40, 48) else 0
                flow_lpm = 3.2 if pump_on else 0.0
                telemetry_rows.append(
                    Telemetry(
                        device_id=wms1.id,
                        boot_id="seed",
                        seq=i,
                        ts=sample_time,
                        received_at=sample_time,
                        distance_cm=distance_cm,
                        level_pct=level_pct,
                        flow_lpm=flow_lpm,
                        flow_total_l=round(i * 0.8, 1),
                        pump_on=pump_on,
                        fault="",
                        rssi=-60,
                    )
                )
            db.add_all(telemetry_rows)
            db.flush()

        # 5. Seed Users
        users_spec = [
            ("admin@wms.io", "System Administrator", "admin", "SEED_ADMIN_PASSWORD"),
            ("operator_a@wms.io", "Operator Khu A", "operator", "SEED_OPERATOR_A_PASSWORD"),
            ("operator_b@wms.io", "Operator Khu B", "operator", "SEED_OPERATOR_B_PASSWORD"),
            ("viewer@wms.io", "Viewer Khu A", "viewer", "SEED_VIEWER_PASSWORD"),
        ]

        created_credentials: list[tuple[str, str, str]] = []
        user_map: dict[str, User] = {}

        for email, full_name, role, env_var in users_spec:
            user = db.query(User).filter(User.email == email).first()
            if not user:
                raw_pw = os.environ.get(env_var) or secrets.token_urlsafe(12)
                user = User(
                    email=email,
                    password_hash=_hash_password(raw_pw),
                    full_name=full_name,
                    role=role,
                    status="active",
                    token_version=0,
                )
                db.add(user)
                db.flush()
                created_credentials.append((email, role, raw_pw))
            user_map[email] = user

        # 6. Assign Operator A & Viewer -> wms-001; Operator B -> wms-002
        assignments = [
            (user_map["operator_a@wms.io"].id, device_map["wms-001"].id),
            (user_map["viewer@wms.io"].id, device_map["wms-001"].id),
            (user_map["operator_b@wms.io"].id, device_map["wms-002"].id),
        ]
        for uid, did in assignments:
            exists = (
                db.query(UserDevice)
                .filter(
                    UserDevice.user_id == uid,
                    UserDevice.device_id == did,
                )
                .first()
            )
            if not exists:
                db.add(UserDevice(user_id=uid, device_id=did))

        db.commit()

        if created_credentials:
            print("=== TAI KHOAN MAU VUA TAO (CHI HIEN THI 1 LAN) ===")
            for email, role, pw in created_credentials:
                print(f"  - {email} ({role}): {pw}")
            print("==================================================")
        else:
            print("[seed_dev] Cac tai khoan va thiet bi mau da ton tai.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
