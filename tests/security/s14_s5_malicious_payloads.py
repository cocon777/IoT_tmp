"""Security test S5: Send and validate malicious telemetry payloads (`payloads_s05.json`).

Can be executed standalone now (validating `validate_telemetry_payload` + publishing over
MQTT to `wms/wms-001/telemetry`) and re-run after integrating TV2's telemetry ingest.
Saves evidence to `docs/evidence/s5-payload-validation.txt`.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import paho.mqtt.client as mqtt

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
for candidate in (ROOT_DIR / "backend", ROOT_DIR):
    if (candidate / "app").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.config import settings  # noqa: E402
from app.security.device_guard import validate_telemetry_payload  # noqa: E402


def main() -> None:
    """Validate and publish malicious payloads from payloads_s05.json."""
    payloads_path = Path(__file__).resolve().parent / "payloads_s05.json"
    evidence_path = ROOT_DIR / "docs" / "evidence" / "s5-payload-validation.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    cases = json.loads(payloads_path.read_text(encoding="utf-8"))
    lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        lines.append(msg)

    log("=== KIEM THU BAO MAT S5 (BUOC S14): KIEM TRA & LOAI BO PAYLOAD DOC HAI ===")
    log(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    log(f"File dau vao: tests/security/payloads_s05.json ({len(cases)} kich ban)")
    log("--------------------------------------------------------------------------")

    pub_client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="s14-s5-payload-sender",
    )
    pub_client.username_pw_set(
        settings.mqtt_backend_user, settings.mqtt_backend_password
    )
    mqtt_connected = False
    try:
        pub_client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=10)
        pub_client.loop_start()
        mqtt_connected = True
    except Exception as exc:  # noqa: BLE001
        log(f"[WARN] Khong ket noi duoc broker MQTT ({exc}), chi chay bo loc truc tiep.")

    try:
        passed = 0
        for case in cases:
            raw_json = json.dumps(case["payload"], ensure_ascii=False)
            if mqtt_connected:
                pub_client.publish(
                    "wms/wms-001/telemetry", payload=raw_json, qos=1
                ).wait_for_publish(timeout=3.0)

            is_valid, reason = validate_telemetry_payload(raw_json)
            assert not is_valid, f"Case {case['id']} should have been rejected!"
            assert reason == case["expected_reason"], (
                f"Case {case['id']}: expected {case['expected_reason']}, got {reason}"
            )
            log(
                f"[PASS] {case['id']} ({case['description']}) -> Bi loai bo | "
                f"reason={reason}"
            )
            passed += 1

        log("--------------------------------------------------------------------------")
        log(f"KET QUA S5: {passed}/{len(cases)} PASS (Tat ca payload sai/doc hai deu bi loai bo va ghi log)")
        evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        if mqtt_connected:
            pub_client.disconnect()
            pub_client.loop_stop()


if __name__ == "__main__":
    main()
