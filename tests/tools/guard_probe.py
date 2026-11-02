"""Test subscriber probe (`guard_probe.py`) for S12 second-layer backend device guard.

NOTE: This is a verification probe (not TV2's real telemetry ingest). It connects
to the MQTT broker as `backend`, subscribes to `wms/+/telemetry`, and runs every
incoming message through `inspect_incoming_message` (`check_payload_size`,
`check_device_rate_limit`, and `is_device_active`).
"""

from __future__ import annotations

import logging
from pathlib import Path
import sys
import threading
import time
from typing import Any

import paho.mqtt.client as mqtt
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
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
    reset_device_rate_limits,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


class GuardProbeSubscriber:
    """Lightweight MQTT subscriber probe validating S12 device guard filters."""

    def __init__(
        self,
        db: Session,
        *,
        max_bytes: int = 2048,
        max_messages: int = 5,
        window_seconds: float = 10.0,
    ) -> None:
        self.db = db
        self.max_bytes = max_bytes
        self.max_messages = max_messages
        self.window_seconds = window_seconds
        self.accepted_messages: list[tuple[str, str]] = []
        self.dropped_messages: list[tuple[str, str]] = []

    def handle_mqtt_message(self, topic: str, payload: bytes) -> tuple[bool, str]:
        """Process a single MQTT message on `wms/{deviceId}/telemetry`."""
        parts = topic.split("/")
        device_code = parts[1] if len(parts) >= 3 else ""
        accepted, reason = inspect_incoming_message(
            device_code,
            payload,
            db=self.db,
            max_bytes=self.max_bytes,
            max_messages=self.max_messages,
            window_seconds=self.window_seconds,
        )
        if accepted:
            self.accepted_messages.append(
                (device_code, payload.decode("utf-8", errors="replace"))
            )
        else:
            self.dropped_messages.append((device_code, reason))
        return accepted, reason


def run_live_broker_probe() -> None:
    """Verify S12 guard over live MQTT broker (`mosquitto`) with simulated publishes."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    reset_device_rate_limits()
    dev = DeviceStub(id=1, device_code="wms-001", name="Main Tank", state="Active")
    db.add(dev)
    db.commit()

    probe = GuardProbeSubscriber(db, max_bytes=2048, max_messages=3, window_seconds=10.0)
    ready_evt = threading.Event()
    msg_Lock = threading.Lock()

    sub_client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="s12-guard-probe-sub",
    )
    sub_client.username_pw_set(
        settings.mqtt_backend_user, settings.mqtt_backend_password
    )

    def on_connect(
        c: mqtt.Client, _ud: Any, _fl: Any, rc: Any, _pr: Any = None
    ) -> None:
        if rc == 0:
            c.subscribe("wms/+/telemetry", qos=1)
            ready_evt.set()

    def on_message(_c: mqtt.Client, _ud: Any, msg: mqtt.MQTTMessage) -> None:
        with msg_Lock:
            probe.handle_mqtt_message(msg.topic, msg.payload)

    sub_client.on_connect = on_connect
    sub_client.on_message = on_message
    sub_client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=15)
    sub_client.loop_start()
    assert ready_evt.wait(timeout=5.0), "Guard probe failed to subscribe"

    pub_client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="s12-guard-probe-pub",
    )
    pub_client.username_pw_set(
        settings.mqtt_backend_user, settings.mqtt_backend_password
    )
    pub_client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=15)
    pub_client.loop_start()

    try:
        # 1. Active device normal payload -> accepted
        pub_client.publish(
            "wms/wms-001/telemetry",
            payload='{"device_id":"wms-001","seq":1,"level_pct":70.0}',
            qos=1,
        ).wait_for_publish(timeout=3.0)
        time.sleep(0.3)

        # 2. Switch wms-001 to Decommissioned -> dropped with device_not_active
        dev.state = "Decommissioned"
        db.add(dev)
        db.commit()

        pub_client.publish(
            "wms/wms-001/telemetry",
            payload='{"device_id":"wms-001","seq":2,"level_pct":71.0}',
            qos=1,
        ).wait_for_publish(timeout=3.0)
        time.sleep(0.3)

        # 3. Restore Active, send oversized payload (> 2 KB) -> dropped with payload_too_large
        dev.state = "Active"
        db.add(dev)
        db.commit()
        oversized = '{"device_id":"wms-001","padding":"' + ("X" * 2500) + '"}'
        pub_client.publish(
            "wms/wms-001/telemetry",
            payload=oversized,
            qos=1,
        ).wait_for_publish(timeout=3.0)
        time.sleep(0.3)

        # 4. Send burst of 4 messages (limit is 3 in window; 2 already counted) -> rate_limit_exceeded
        for seq in range(3, 6):
            pub_client.publish(
                "wms/wms-001/telemetry",
                payload=f'{{"device_id":"wms-001","seq":{seq},"level_pct":72.0}}',
                qos=1,
            ).wait_for_publish(timeout=3.0)
        time.sleep(0.5)

        drop_reasons = [r for _, r in probe.dropped_messages]
        print(f"[guard_probe] Accepted count: {len(probe.accepted_messages)}")
        print(f"[guard_probe] Dropped reasons: {drop_reasons}")
        assert "device_not_active" in drop_reasons
        assert "payload_too_large" in drop_reasons
        assert "rate_limit_exceeded" in drop_reasons
        print("[guard_probe] PASS: Decommissioned, oversized (>2KB), and burst floods were all dropped!")
    finally:
        pub_client.disconnect()
        pub_client.loop_stop()
        sub_client.disconnect()
        sub_client.loop_stop()
        db.close()


if __name__ == "__main__":
    run_live_broker_probe()
