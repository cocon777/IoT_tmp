"""Automated verification script for S11 Dynamic Security & S3 broker revocation evidence.

Runs:
1. `create_client("wms-test", ...)` -> connects, publishes allowed topic (`wms/wms-test/telemetry`)
   and verifies unauthorized publish (`wms/other/telemetry`) is blocked by ACL.
2. `disable_client("wms-test")` -> verifies connection is rejected; `enable_client("wms-test")`
   restores connection.
3. `delete_client("wms-test")` while `wms-test` is actively connected -> verifies active
   connection is immediately kicked by the broker and reconnection is rejected.
   Saves log to `docs/evidence/s3-broker-revoke.txt`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import threading
import time
from typing import Any

import paho.mqtt.client as mqtt

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
for candidate in (ROOT_DIR / "backend", ROOT_DIR):
    if (candidate / "app").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.config import settings  # noqa: E402
from app.services import broker_admin  # noqa: E402


def _try_connect(
    username: str,
    password: str,
    host: str,
    port: int,
    timeout: float = 4.0,
) -> tuple[bool, str]:
    """Attempt MQTT connection and return (connected_ok, reason_str)."""
    connected_evt = threading.Event()
    state: dict[str, Any] = {"ok": False, "reason": "timeout"}

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"probe-{username}-{int(time.time() * 1000)}",
    )
    client.username_pw_set(username, password)

    def on_connect(
        _c: mqtt.Client,
        _ud: Any,
        _flags: Any,
        rc: Any,
        _props: Any = None,
    ) -> None:
        state["ok"] = rc == 0
        state["reason"] = str(rc)
        connected_evt.set()

    client.on_connect = on_connect
    try:
        client.connect(host, port, keepalive=10)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)

    client.loop_start()
    try:
        connected_evt.wait(timeout=timeout)
    finally:
        client.disconnect()
        client.loop_stop()

    return bool(state["ok"]), str(state["reason"])


def main() -> None:
    """Execute S11 Dynamic Security verification and write docs/evidence/s3-broker-revoke.txt."""
    evidence_path = ROOT_DIR / "docs" / "evidence" / "s3-broker-revoke.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    host = settings.mqtt_host
    port = settings.mqtt_port
    lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    log("=== KIEM THU BAO MAT S11 / S3: MOSQUITTO DYNAMIC SECURITY & THU HOI THIET BI ===")
    log(f"Broker: {host}:{port}")
    log(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    log("--------------------------------------------------------------------------------")

    # Start backend subscriber to observe delivered messages on wms/#
    delivered_topics: list[str] = []
    be_ready = threading.Event()
    be_client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="be-observer-s11",
    )
    be_client.username_pw_set(
        settings.mqtt_backend_user, settings.mqtt_backend_password
    )

    def on_be_connect(
        c: mqtt.Client, _ud: Any, _fl: Any, rc: Any, _pr: Any = None
    ) -> None:
        if rc == 0:
            c.subscribe("wms/#", qos=1)
            be_ready.set()

    def on_be_msg(_c: mqtt.Client, _ud: Any, msg: mqtt.MQTTMessage) -> None:
        delivered_topics.append(msg.topic)

    be_client.on_connect = on_be_connect
    be_client.on_message = on_be_msg
    be_client.connect(host, port, keepalive=15)
    be_client.loop_start()
    assert be_ready.wait(timeout=5.0), "Backend observer failed to connect"

    try:
        # 1. create_client("wms-test") -> connect and verify ACL
        creds = broker_admin.create_client("wms-test", host=host, port=port)
        raw_pw = creds["password"]
        assert creds["password_hash"].startswith("$2b$")

        ok_conn, reason_conn = _try_connect("wms-test", raw_pw, host, port)
        assert ok_conn, f"Expected wms-test connect success, got {reason_conn}"

        # Publish to allowed topic wms/wms-test/telemetry and forbidden topic wms/other/telemetry
        dev_pub = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="wms-test-pub",
        )
        dev_pub.username_pw_set("wms-test", raw_pw)
        dev_pub.connect(host, port, keepalive=10)
        dev_pub.loop_start()
        info_ok = dev_pub.publish(
            "wms/wms-test/telemetry",
            payload='{"device_id":"wms-test","level_pct":80.0}',
            qos=1,
        )
        info_ok.wait_for_publish(timeout=3.0)
        dev_pub.publish(
            "wms/other/telemetry",
            payload='{"device_id":"other","level_pct":10.0}',
            qos=1,
        )
        time.sleep(0.8)
        dev_pub.disconnect()
        dev_pub.loop_stop()

        assert "wms/wms-test/telemetry" in delivered_topics
        assert "wms/other/telemetry" not in delivered_topics
        log(
            "[PASS] 1. create_client('wms-test'): ket noi thanh cong, publish wms/wms-test/telemetry "
            "duoc nhan, publish wms/other/telemetry bi ACL chan."
        )

        # 2. disable_client("wms-test") -> connection rejected; enable_client -> restored
        broker_admin.disable_client("wms-test", host=host, port=port)
        ok_disabled, reason_disabled = _try_connect("wms-test", raw_pw, host, port)
        assert not ok_disabled, "Expected disabled client to be rejected"
        log(
            f"[PASS] 2. disable_client('wms-test'): ket noi lai bi tu choi ngay (reason={reason_disabled})."
        )

        broker_admin.enable_client("wms-test", host=host, port=port)
        ok_reenabled, _ = _try_connect("wms-test", raw_pw, host, port)
        assert ok_reenabled, "Expected re-enabled client to connect"
        log("[PASS] 2b. enable_client('wms-test'): kich hoat lai va ket noi thanh cong.")

        # 3. delete_client("wms-test") while actively connected -> kicked & cannot reconnect
        kicked_evt = threading.Event()
        active_evt = threading.Event()
        live_client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="wms-test-live-session",
        )
        live_client.username_pw_set("wms-test", raw_pw)

        def on_live_connect(
            _c: mqtt.Client, _ud: Any, _fl: Any, rc: Any, _pr: Any = None
        ) -> None:
            if rc == 0:
                active_evt.set()

        def on_live_disconnect(
            _c: mqtt.Client, _ud: Any, _fl: Any, rc: Any, _pr: Any = None
        ) -> None:
            kicked_evt.set()

        live_client.on_connect = on_live_connect
        live_client.on_disconnect = on_live_disconnect
        live_client.connect(host, port, keepalive=15)
        live_client.loop_start()
        assert active_evt.wait(timeout=4.0), "Live session failed to connect"

        # Revoke / delete client while session is open
        broker_admin.delete_client("wms-test", host=host, port=port)
        was_kicked = kicked_evt.wait(timeout=4.0)
        live_client.loop_stop()
        assert was_kicked, "Active MQTT session was not disconnected upon delete_client"

        ok_after_delete, reason_after_delete = _try_connect(
            "wms-test", raw_pw, host, port
        )
        assert not ok_after_delete, "Deleted client was still able to connect!"
        log(
            f"[PASS] 3. delete_client('wms-test') khi dang ket noi: phien MQTT dang mo bi ngat tuc thi "
            f"(kicked={was_kicked}) va ket noi lai bi tu choi (reason={reason_after_delete})."
        )

        log("--------------------------------------------------------------------------------")
        log("KET QUA S11 / S3 (MUC BROKER): 3/3 PASS")
        evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        be_client.disconnect()
        be_client.loop_stop()


if __name__ == "__main__":
    main()
