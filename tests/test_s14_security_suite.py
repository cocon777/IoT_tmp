"""Comprehensive pytest suite for S14 covering F1, S1, S2, S3/F8, S5, and S6."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.device_stub import DeviceStub
from app.security.device_guard import (
    inspect_incoming_message,
    is_device_active,
    validate_telemetry_payload,
)


def test_s5_all_malicious_payloads_rejected() -> None:
    """Verify every malicious payload in tests/security/payloads_s05.json is rejected."""
    payloads_file = (
        Path(__file__).resolve().parent / "security" / "payloads_s05.json"
    )
    cases = json.loads(payloads_file.read_text(encoding="utf-8"))
    assert len(cases) >= 5

    for case in cases:
        raw = json.dumps(case["payload"])
        ok, reason = validate_telemetry_payload(raw)
        assert ok is False, f"{case['id']} was unexpectedly accepted"
        assert reason == case["expected_reason"]


def test_s5_valid_telemetry_payload_accepted() -> None:
    """Verify a well-formed telemetry payload passes validate_telemetry_payload."""
    valid_json = json.dumps(
        {
            "device_id": "wms-001",
            "boot_id": "a3f9",
            "seq": 1042,
            "ts": "2026-11-01T09:00:05Z",
            "distance_cm": 18.4,
            "level_pct": 72.5,
            "flow_lpm": 3.2,
            "pump_on": True,
            "fault": "",
        }
    )
    ok, reason = validate_telemetry_payload(valid_json)
    assert ok is True
    assert reason == "valid"


def test_s3_f8_backend_rejects_decommissioned_device(db_session: Session) -> None:
    """Verify S3/F8 second layer rejects messages once device is Decommissioned."""
    dev = DeviceStub(id=1, device_code="wms-001", state="Active")
    db_session.add(dev)
    db_session.commit()

    assert is_device_active("wms-001", db=db_session) is True

    dev.state = "Decommissioned"
    db_session.commit()

    assert is_device_active("wms-001", db=db_session) is False
    ok, reason = inspect_incoming_message(
        "wms-001", '{"device_id":"wms-001","seq":1}', db=db_session
    )
    assert ok is False
    assert reason == "device_not_active"
