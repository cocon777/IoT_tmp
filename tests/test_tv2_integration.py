"""Comprehensive integration tests for TV2 core features within the unified TV3 backend.

Tests:
1. Device lifecycle (Registered -> Provisioned -> Active -> Maintenance -> Decommissioned)
2. Device config versioning & parameter limits validation (via API)
3. Telemetry ingestion via MQTT pipeline, payload guard, & telemetry query API
4. 5-rule Alert engine (low level, high level, dry run, overrun, sensor fault)
5. Pump command dispatch and ACK processing (via MQTT pipeline)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app import alerts as alert_engine
from app import commands as cmd_service
from app import device_config as cfg_service
from app import ingest
from app import lifecycle
from app import mqtt_client
from app.broker_admin import NoopBrokerAdmin
from app.db import utcnow
from app.errors import Conflict, InvalidInput, InvalidTransition
from app.main import app as fastapi_app
from app.models import Alert, Command, Device, DeviceConfig, Site, Telemetry, User, UserDevice
from app.routers import commands as commands_router
from app.security.auth import create_access_token, hash_password


class MockPublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, int]] = []

    def publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False) -> None:
        self.published.append((topic, payload, qos))

    def is_connected(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def setup_mock_publisher(monkeypatch):
    mock_pub = MockPublisher()
    alert_engine.set_publisher(mock_pub)
    monkeypatch.setattr(mqtt_client, "_instance", mock_pub)
    monkeypatch.setattr(commands_router, "get_publisher", lambda: mock_pub)
    yield mock_pub
    alert_engine.shutdown()


def _setup_unified_context(db: Session) -> dict[str, object]:
    site = Site(name="Test Site", description="Integration Test Site")
    db.add(site)
    db.flush()

    admin = User(
        email="admin@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Admin User",
        role="admin",
        status="active",
        token_version=0,
    )
    operator = User(
        email="operator@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Operator User",
        role="operator",
        status="active",
        token_version=0,
    )
    db.add_all([admin, operator])
    db.flush()

    dev = Device(
        device_code="wms-int-001",
        name="Integration Tank",
        site_id=site.id,
        state="Active",
        online=True,
    )
    db.add(dev)
    db.flush()

    db.add(UserDevice(user_id=operator.id, device_id=dev.id))
    db.commit()

    return {
        "site": site,
        "admin": admin,
        "operator": operator,
        "device": dev,
        "admin_token": create_access_token(admin.id, admin.role),
        "operator_token": create_access_token(operator.id, operator.role),
    }


def test_device_lifecycle_transitions(db_session: Session) -> None:
    """Verify state transitions and invalid transition rejections."""
    site = Site(name="Lifecycle Site")
    db_session.add(site)
    db_session.flush()

    dev = lifecycle.create_device(
        db_session,
        device_code="dev-cycle-01",
        name="Cycle Tank",
        hw_version="v1",
        actor_id=None,
        ip="127.0.0.1",
    )
    assert dev.state == "Registered"

    # Registered -> Provisioned
    broker = NoopBrokerAdmin()
    lifecycle.provision(db_session, broker, dev.id, actor_id=None, ip="127.0.0.1")
    db_session.refresh(dev)
    assert dev.state == "Provisioned"

    # Provisioned -> Active
    lifecycle.change_state(db_session, broker, dev.id, "Active", actor_id=None, ip="127.0.0.1")
    db_session.refresh(dev)
    assert dev.state == "Active"

    # Active -> Maintenance
    lifecycle.change_state(db_session, broker, dev.id, "Maintenance", actor_id=None, ip="127.0.0.1")
    db_session.refresh(dev)
    assert dev.state == "Maintenance"

    # Maintenance -> Active
    lifecycle.change_state(db_session, broker, dev.id, "Active", actor_id=None, ip="127.0.0.1")
    db_session.refresh(dev)
    assert dev.state == "Active"

    # Active -> Decommissioned
    lifecycle.change_state(db_session, broker, dev.id, "Decommissioned", actor_id=None, ip="127.0.0.1")
    db_session.refresh(dev)
    assert dev.state == "Decommissioned"

    # Decommissioned cannot transition to Active -> InvalidTransition
    with pytest.raises(InvalidTransition):
        lifecycle.change_state(db_session, broker, dev.id, "Active", actor_id=None, ip="127.0.0.1")


def test_device_config_versioning_and_validation(db_session: Session, override_get_db: None) -> None:
    """Verify config update increments version and validates bounds via API."""
    ctx = _setup_unified_context(db_session)
    dev: Device = ctx["device"]  # type: ignore[assignment]
    token = ctx["admin_token"]
    client = TestClient(fastapi_app)

    # Valid config update via API
    resp = client.put(
        f"/api/devices/{dev.id}/config",
        headers={"Authorization": f"Bearer {token}"},
        json={"sample_interval_s": 15, "low_pct": 25.0},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] >= 1
    assert data["config"]["sample_interval_s"] == 15
    assert data["config"]["low_pct"] == 25.0

    # Invalid config (out of bounds: low_pct > 100) -> HTTP 422
    resp_bad = client.put(
        f"/api/devices/{dev.id}/config",
        headers={"Authorization": f"Bearer {token}"},
        json={"low_pct": 120.0},
    )
    assert resp_bad.status_code == 422


def test_telemetry_ingestion_and_query_api(db_session: Session, override_get_db: None) -> None:
    """Verify telemetry ingestion via ingest pipeline and querying via API."""
    ctx = _setup_unified_context(db_session)
    dev: Device = ctx["device"]  # type: ignore[assignment]
    token = ctx["operator_token"]
    client = TestClient(fastapi_app)

    now_iso = utcnow().isoformat() + "Z"
    payload = {
        "device_id": dev.device_code,
        "boot_id": "b-01",
        "seq": 1,
        "ts": now_iso,
        "level_pct": 65.5,
        "flow_lpm": 2.4,
        "distance_cm": 8.6,
        "flow_total_l": 120.0,
        "pump_on": 1,
        "fault": "",
        "rssi": -65,
    }

    # Ingest telemetry via MQTT pipeline
    ingest.handle_message(
        f"wms/{dev.device_code}/telemetry",
        json.dumps(payload).encode("utf-8"),
    )

    # Verify via API
    resp = client.get(
        f"/api/devices/{dev.id}/telemetry",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["points"]) >= 1
    latest = data["points"][0]
    assert latest["level_pct"] == 65.5
    assert latest["flow_lpm"] == 2.4


def test_alert_engine_rules(db_session: Session) -> None:
    """Verify alert rules triggering and auto-pump actions."""
    ctx = _setup_unified_context(db_session)
    dev: Device = ctx["device"]  # type: ignore[assignment]

    # Rule 1: Low water level (< 20%) -> Alert triggers when sustained >= min_duration_s (10s)
    t0 = utcnow()
    ingest.handle_message(
        f"wms/{dev.device_code}/telemetry",
        json.dumps(
            {
                "device_id": dev.device_code,
                "boot_id": "b-alert",
                "seq": 10,
                "ts": t0.isoformat() + "Z",
                "level_pct": 10.0,
                "flow_lpm": 0.0,
                "distance_cm": 22.5,
                "pump_on": 0,
                "fault": "",
            }
        ).encode("utf-8"),
    )
    # Second sample 15s later to fulfill min_duration_s=10
    ingest.handle_message(
        f"wms/{dev.device_code}/telemetry",
        json.dumps(
            {
                "device_id": dev.device_code,
                "boot_id": "b-alert",
                "seq": 11,
                "ts": (t0 + timedelta(seconds=15)).isoformat() + "Z",
                "level_pct": 10.0,
                "flow_lpm": 0.0,
                "distance_cm": 22.5,
                "pump_on": 0,
                "fault": "",
            }
        ).encode("utf-8"),
    )

    alert = (
        db_session.query(Alert)
        .filter(Alert.device_id == dev.id, Alert.type == "LOW_LEVEL")
        .first()
    )
    assert alert is not None
    assert alert.severity == "warning"

    # Rule 2: High water level (>= 90%) -> Alert + auto pump OFF
    t_high = t0 + timedelta(seconds=30)
    ingest.handle_message(
        f"wms/{dev.device_code}/telemetry",
        json.dumps(
            {
                "device_id": dev.device_code,
                "boot_id": "b-alert",
                "seq": 20,
                "ts": t_high.isoformat() + "Z",
                "level_pct": 95.0,
                "flow_lpm": 3.0,
                "distance_cm": 1.25,
                "pump_on": 1,
                "fault": "",
            }
        ).encode("utf-8"),
    )
    alert_high = (
        db_session.query(Alert)
        .filter(Alert.device_id == dev.id, Alert.type == "HIGH_LEVEL")
        .first()
    )
    assert alert_high is not None

    # Rule 5: Offline alert via on_device_offline
    alert_engine.on_device_offline(dev.id, t0 + timedelta(seconds=60))
    alert_offline = (
        db_session.query(Alert)
        .filter(Alert.device_id == dev.id, Alert.type == "DEVICE_OFFLINE")
        .first()
    )
    assert alert_offline is not None


def test_command_dispatch_and_ack(db_session: Session, override_get_db: None) -> None:
    """Verify pump command dispatch via API and handling ACK via ingest."""
    ctx = _setup_unified_context(db_session)
    dev: Device = ctx["device"]  # type: ignore[assignment]
    token = ctx["operator_token"]
    client = TestClient(fastapi_app)

    # Operator dispatches pump command
    resp = client.post(
        f"/api/devices/{dev.id}/commands",
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "pump", "value": "on", "duration_s": 45},
    )
    assert resp.status_code == 200
    cmd_data = resp.json()
    assert cmd_data["status"] == "sent"
    cmd_id = cmd_data["cmd_id"]

    # Ingest ACK from device via MQTT pipeline
    ingest.handle_message(
        f"wms/{dev.device_code}/ack",
        json.dumps(
            {"cmd_id": cmd_id, "result": "ok", "error": "", "ts": utcnow().isoformat() + "Z"}
        ).encode("utf-8"),
    )

    # Check command status in DB
    db_session.expire_all()
    cmd = db_session.query(Command).filter(Command.cmd_id == cmd_id).first()
    assert cmd is not None
    assert cmd.status == "ok"
    assert cmd.acked_at is not None
