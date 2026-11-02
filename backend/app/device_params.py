"""Device configuration defaults, bounds, and validation (TV2)."""

import json
import math
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.device import DeviceConfig

DEFAULTS: dict[str, Any] = {
    "sample_interval_s": 5,
    "tank_height_cm": 25.0,
    "low_pct": 20.0,
    "high_pct": 90.0,
    "pump_max_run_s": 120,
    "auto_mode": True,
    "dry_run_s": 10,
}
MIN_BAND_PCT = 10


class InvalidConfigInput(ValueError):
    """Raised when a device config update violates type or range constraints."""


def limits() -> dict[str, dict[str, Any]]:
    """Return valid type and min/max bounds for each configuration parameter."""
    return {
        "sample_interval_s": {"type": "int", "min": 1, "max": 300},
        "tank_height_cm": {"type": "float", "min": 5, "max": 500},
        "low_pct": {"type": "float", "min": 0, "max": 100},
        "high_pct": {"type": "float", "min": 0, "max": 100},
        "pump_max_run_s": {"type": "int", "min": 5, "max": settings.pump_max_duration_s},
        "auto_mode": {"type": "bool", "min": None, "max": None},
        "dry_run_s": {"type": "int", "min": 3, "max": 120},
    }


def _parse(key: str, raw: str) -> Any:
    default = DEFAULTS[key]
    try:
        if isinstance(default, bool):
            return str(raw).strip().lower() in ("true", "1", "yes")
        if isinstance(default, int):
            return int(float(raw))
        return float(raw)
    except (TypeError, ValueError):
        return default


def store(value: Any) -> str:
    """Serialize configuration value to JSON string for `device_configs.value`."""
    return json.dumps(value)


def get_config(s: Session, device_id: int) -> dict[str, Any]:
    """Load effective configuration for `device_id` merged with `DEFAULTS`."""
    cfg = dict(DEFAULTS)
    for row in s.scalars(select(DeviceConfig).where(DeviceConfig.device_id == device_id)):
        if row.key in DEFAULTS:
            cfg[row.key] = _parse(row.key, row.value)
    return cfg


def get_version(s: Session, device_id: int) -> int:
    """Return current configuration version for `device_id` (0 if using defaults)."""
    return (
        s.scalar(
            select(func.max(DeviceConfig.version)).where(
                DeviceConfig.device_id == device_id
            )
        )
        or 0
    )


def to_public(cfg: dict[str, Any]) -> dict[str, Any]:
    """Format configuration dictionary for API and MQTT wire responses."""
    return {
        k: (int(v) if isinstance(v, float) and v.is_integer() else v)
        for k, v in ((k, cfg[k]) for k in DEFAULTS)
    }


def to_wire(cfg: dict[str, Any], version: int) -> dict[str, Any]:
    """Build retained MQTT payload for `wms/{deviceId}/config`."""
    return {"version": version, **to_public(cfg)}


def _coerce(key: str, raw: Any, lim: dict[str, Any]) -> Any:
    from app.errors import InvalidInput

    if lim["type"] == "bool":
        if not isinstance(raw, bool):
            raise InvalidInput(f"{key} phải là true hoặc false")
        return raw
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        raise InvalidInput(f"{key} phải là một số")
    if lim["type"] == "int":
        if isinstance(raw, float) and not raw.is_integer():
            raise InvalidInput(f"{key} phải là số nguyên")
        value: int | float = int(raw)
    else:
        value = float(raw)
    if not (lim["min"] <= value <= lim["max"]):
        raise InvalidInput(f"{key} phải trong khoảng {lim['min']}..{lim['max']}")
    return value


def validate_update(updates: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Validate config updates and return only keys whose values actually changed."""
    from app.errors import InvalidInput

    lim = limits()
    merged, changes = dict(current), {}
    for key, raw in updates.items():
        if key not in DEFAULTS:
            raise InvalidInput(f"Khóa cấu hình không hợp lệ: {key}")
        value = _coerce(key, raw, lim[key])
        merged[key] = value
        if value != current[key]:
            changes[key] = value
    if merged["high_pct"] - merged["low_pct"] < MIN_BAND_PCT:
        raise InvalidInput(
            f"high_pct phải lớn hơn low_pct ít nhất {MIN_BAND_PCT} điểm phần trăm"
        )
    return changes
