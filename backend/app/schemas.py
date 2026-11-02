"""Pydantic schemas for MQTT telemetry, status, and command acknowledgements (TV2)."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TelemetryIn(BaseModel):
    """MQTT payload schema for `wms/{deviceId}/telemetry` (enforces range bounds, S5)."""

    model_config = ConfigDict(extra="ignore")

    device_id: str | int = Field(default="")
    boot_id: str = Field(min_length=1, max_length=16)
    seq: int = Field(ge=0, le=2**53)
    ts: datetime
    distance_cm: float = Field(default=0.0, ge=0, le=1000)
    level_pct: float = Field(ge=0, le=100)
    flow_lpm: float = Field(ge=0, le=100)
    flow_total_l: float = Field(default=0.0, ge=0)
    pump_on: bool
    fault: str = Field(default="", max_length=64)
    rssi: int | None = Field(default=None, ge=-120, le=0)

    @field_validator("ts")
    @classmethod
    def ts_to_naive_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("ts phải có múi giờ (ví dụ hậu tố Z)")
        return v.astimezone(timezone.utc).replace(tzinfo=None)


class StatusIn(BaseModel):
    """MQTT payload schema for `wms/{deviceId}/status` (online/heartbeat/LWT)."""

    model_config = ConfigDict(extra="ignore")

    status: Literal["online", "offline"]
    fw_version: str | None = Field(default=None, max_length=32)
    free_heap: int | None = Field(default=None, ge=0)
    config_version: int | None = Field(default=None, ge=0)


class UserOut(BaseModel):
    """Public user representation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str
    status: str
    locked: bool = False
    created_at: datetime


class AckIn(BaseModel):
    """MQTT payload schema for `wms/{deviceId}/ack`."""

    model_config = ConfigDict(extra="ignore")

    cmd_id: str = Field(min_length=1, max_length=64)
    result: Literal["ok", "fail"]
    reason: str | None = Field(default=None, max_length=128)
    ts: datetime | None = None
