"""Unit tests for S12 backend device guard (`is_device_active`, payload size, rate limit)."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models.device_stub import DeviceStub
from app.security.device_guard import (
    check_device_rate_limit,
    check_payload_size,
    inspect_incoming_message,
    is_device_active,
    reset_device_rate_limits,
)


@pytest.fixture(autouse=True)
def _reset_limits() -> None:
    reset_device_rate_limits()


def test_is_device_active_checks_lifecycle_state(db_session: Session) -> None:
    """Only devices in state=='Active' return True; Decommissioned/Maintenance/Offline return False."""
    d_active = DeviceStub(id=1, device_code="wms-001", state="Active")
    d_decomm = DeviceStub(id=2, device_code="wms-002", state="Decommissioned")
    d_maint = DeviceStub(id=3, device_code="wms-003", state="Maintenance")
    db_session.add_all([d_active, d_decomm, d_maint])
    db_session.commit()

    assert is_device_active(1, db=db_session) is True
    assert is_device_active("wms-001", db=db_session) is True

    assert is_device_active(2, db=db_session) is False
    assert is_device_active("wms-002", db=db_session) is False

    assert is_device_active(3, db=db_session) is False
    assert is_device_active("wms-999", db=db_session) is False


def test_payload_size_and_device_rate_limit_guards(db_session: Session) -> None:
    """Verify oversized (>2KB) payloads and excessive message bursts are rejected."""
    dev = DeviceStub(id=1, device_code="wms-001", state="Active")
    db_session.add(dev)
    db_session.commit()

    # 1. Oversized payload (> 2048 bytes)
    assert check_payload_size("a" * 2048) is True
    assert check_payload_size("a" * 2049) is False
    ok_big, reason_big = inspect_incoming_message(
        "wms-001", "x" * 2500, db=db_session
    )
    assert ok_big is False
    assert reason_big == "payload_too_large"

    # 2. Decommissioned device dropped
    dev.state = "Decommissioned"
    db_session.commit()
    ok_decomm, reason_decomm = inspect_incoming_message(
        "wms-001", '{"seq":1}', db=db_session
    )
    assert ok_decomm is False
    assert reason_decomm == "device_not_active"

    # 3. Rate limit per device
    dev.state = "Active"
    db_session.commit()
    reset_device_rate_limits()
    for _ in range(3):
        assert check_device_rate_limit("wms-002", max_messages=3, window_seconds=10.0) is True
    assert check_device_rate_limit("wms-002", max_messages=3, window_seconds=10.0) is False
