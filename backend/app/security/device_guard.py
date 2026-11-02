"""Second-layer backend guard for MQTT telemetry ingestion (`is_device_active`, S12).

Provides the shared interface functions handed off to TV2 (section 2.2):
- `is_device_active(device_id, db=None)`
- `check_payload_size(payload, max_bytes=2048)`
- `check_device_rate_limit(device_id, max_messages=20, window_seconds=10.0)`
- `inspect_incoming_message(device_id, payload, db=None, ...)`
"""

from __future__ import annotations

from collections import defaultdict, deque
import json
import logging
import re
import time
from typing import Any

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.device_stub import DeviceStub

logger = logging.getLogger("wms.device_guard")

MAX_PAYLOAD_BYTES: int = 2048  # 2 KB
DEVICE_RATE_LIMIT_MAX_MSGS: int = 20
DEVICE_RATE_LIMIT_WINDOW_SECONDS: float = 10.0

_device_msg_timestamps: dict[str, deque[float]] = defaultdict(deque)


def is_device_active(
    device_id: int | str,
    db: Session | None = None,
) -> bool:
    """Check whether the given device exists and is in the `'Active'` lifecycle state.

    Second-layer defense required by section 1.3 & 2.2: even if a revoked or
    maintenance device still manages to publish to the broker, the backend
    must drop its messages unless `is_device_active(device_id)` returns `True`.

    Accepts either the numeric primary key (`devices.id`) or the string device
    code (`devices.device_code`, e.g. `'wms-001'`).

    Args:
        device_id: Numeric device ID (`int`) or string `device_code` (`str`).
        db: Optional SQLAlchemy session. Opens a short-lived session from
            `SessionLocal` if omitted.

    Returns:
        bool: `True` if the device exists and `device.state == 'Active'`,
            `False` otherwise (including `'Decommissioned'`, `'Maintenance'`,
            `'Offline'`, `'Registered'`, `'Provisioned'`, `'Fault'`, or unknown).
    """
    if device_id is None or device_id == "":
        return False

    session = db
    close_after = False
    if session is None:
        session = SessionLocal()
        close_after = True

    try:
        device: DeviceStub | None = None
        if isinstance(device_id, int) or (
            isinstance(device_id, str) and device_id.isdigit()
        ):
            device = (
                session.query(DeviceStub)
                .filter(DeviceStub.id == int(device_id))
                .first()
            )
        if device is None and isinstance(device_id, str):
            device = (
                session.query(DeviceStub)
                .filter(DeviceStub.device_code == device_id)
                .first()
            )

        if device is None:
            return False
        return device.state == "Active"
    finally:
        if close_after:
            session.close()


def check_payload_size(
    payload: bytes | str,
    max_bytes: int = MAX_PAYLOAD_BYTES,
) -> bool:
    """Check that an incoming MQTT payload does not exceed `max_bytes` (default 2 KB).

    Args:
        payload: Raw MQTT message payload (`bytes` or `str`).
        max_bytes: Maximum allowed payload size in bytes (defaults to 2048).

    Returns:
        bool: `True` if payload size is within limit, `False` if oversized.
    """
    raw_bytes = (
        payload.encode("utf-8", errors="replace")
        if isinstance(payload, str)
        else payload
    )
    return len(raw_bytes) <= max_bytes


def check_device_rate_limit(
    device_id: int | str,
    max_messages: int = DEVICE_RATE_LIMIT_MAX_MSGS,
    window_seconds: float = DEVICE_RATE_LIMIT_WINDOW_SECONDS,
) -> bool:
    """Enforce per-device sliding-window message rate limiting against MQTT floods.

    Args:
        device_id: Device identifier (`id` or `device_code`).
        max_messages: Maximum messages permitted within `window_seconds`.
        window_seconds: Sliding time window in seconds.

    Returns:
        bool: `True` if message is within rate limit, `False` if throttled.
    """
    key = str(device_id)
    now_mono = time.monotonic()
    cutoff = now_mono - window_seconds

    bucket = _device_msg_timestamps[key]
    while bucket and bucket[0] <= cutoff:
        bucket.popleft()

    if len(bucket) >= max_messages:
        return False

    bucket.append(now_mono)
    return True


def reset_device_rate_limits() -> None:
    """Clear in-memory per-device rate limit buckets (used in tests)."""
    _device_msg_timestamps.clear()


def inspect_incoming_message(
    device_id: int | str,
    payload: bytes | str,
    db: Session | None = None,
    *,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    max_messages: int = DEVICE_RATE_LIMIT_MAX_MSGS,
    window_seconds: float = DEVICE_RATE_LIMIT_WINDOW_SECONDS,
) -> tuple[bool, str]:
    """Run all 3 backend ingestion guards (payload size, rate limit, active state).

    Args:
        device_id: Device identifier (`id` or `device_code`).
        payload: Raw MQTT message payload (`bytes` or `str`).
        db: Optional SQLAlchemy session.
        max_bytes: Maximum payload size in bytes (default 2048).
        max_messages: Maximum messages per sliding window.
        window_seconds: Sliding window duration in seconds.

    Returns:
        tuple[bool, str]: `(accepted, reason)` where `accepted` is `True` only
            if all checks pass, and `reason` describes why a message was dropped.
    """
    if not check_payload_size(payload, max_bytes=max_bytes):
        logger.warning(
            "Dropped MQTT message from device=%s: payload exceeds %d bytes",
            device_id,
            max_bytes,
        )
        return False, "payload_too_large"

    if not check_device_rate_limit(
        device_id, max_messages=max_messages, window_seconds=window_seconds
    ):
        logger.warning(
            "Dropped MQTT message from device=%s: rate limit exceeded (%d msgs/%.1fs)",
            device_id,
            max_messages,
            window_seconds,
        )
        return False, "rate_limit_exceeded"

    if not is_device_active(device_id, db=db):
        logger.warning(
            "Dropped MQTT message from device=%s: device is not Active",
            device_id,
        )
        return False, "device_not_active"

    return True, "accepted"


_XSS_SQLI_PATTERN = re.compile(
    r"(<\s*script\b|javascript:|onerror\s*=|onload\s*=|\bUNION\s+SELECT\b|\bDROP\s+TABLE\b|'\s*OR\s+'?1'?\s*=\s*'?1)",
    re.IGNORECASE,
)


def validate_telemetry_payload(payload: bytes | str) -> tuple[bool, str]:
    """Validate telemetry JSON structure, value ranges (`level_pct` in 0..100), required `ts`, and XSS/SQLi strings.

    Can be called by TV2's telemetry ingestion pipeline alongside `inspect_incoming_message`.

    Args:
        payload: Raw MQTT JSON payload (`bytes` or `str`).

    Returns:
        tuple[bool, str]: `(is_valid, reason)` where `is_valid` is `True` if safe and valid.
    """
    if not check_payload_size(payload):
        logger.warning("Rejected telemetry payload: exceeds %d bytes", MAX_PAYLOAD_BYTES)
        return False, "payload_too_large"

    text = (
        payload.decode("utf-8", errors="replace")
        if isinstance(payload, bytes)
        else payload
    )

    if _XSS_SQLI_PATTERN.search(text):
        logger.warning("Rejected telemetry payload: malicious script/SQLi pattern detected")
        return False, "malicious_content_detected"

    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Rejected telemetry payload: invalid JSON")
        return False, "invalid_json"

    if not isinstance(data, dict):
        return False, "invalid_json_object"

    for req_field in ("device_id", "seq", "ts", "level_pct"):
        if req_field not in data or data[req_field] is None or data[req_field] == "":
            logger.warning("Rejected telemetry payload: missing required field '%s'", req_field)
            return False, f"missing_field:{req_field}"

    try:
        level_pct = float(data["level_pct"])
    except (TypeError, ValueError):
        logger.warning("Rejected telemetry payload: non-numeric level_pct")
        return False, "invalid_level_pct_type"

    if not (0.0 <= level_pct <= 100.0):
        logger.warning("Rejected telemetry payload: level_pct=%s out of range [0, 100]", level_pct)
        return False, "level_pct_out_of_range"

    if "flow_lpm" in data and data["flow_lpm"] is not None:
        try:
            flow_lpm = float(data["flow_lpm"])
            if flow_lpm < 0.0:
                return False, "negative_flow_lpm"
        except (TypeError, ValueError):
            return False, "invalid_flow_lpm_type"

    return True, "valid"
