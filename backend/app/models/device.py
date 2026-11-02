"""Core IoT domain ORM models owned by TV2 (Device, Site, Telemetry, Command, Alert, etc.)."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, utcnow

# DATETIME(3): keep millisecond precision on MySQL for latency measurement
DT_MS = DateTime().with_variant(mysql.DATETIME(fsp=3), "mysql")
# BIGINT autoincrement on MySQL; SQLite only autoincrements INTEGER primary keys
BIGINT_PK = BigInteger().with_variant(Integer, "sqlite")


class Site(Base):
    """Physical location/zone where water tanks and IoT nodes are deployed."""

    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")


class Device(Base):
    """IoT node / water tank device (TV2 real Device model replacing DeviceStub)."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_code: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    name: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=""
    )
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("sites.id", ondelete="SET NULL"), nullable=True
    )
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="Registered", index=True
    )
    hw_version: Mapped[str] = mapped_column(String(32), default="")
    fw_version: Mapped[str] = mapped_column(String(32), default="")
    config_applied_version: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __init__(self, **kwargs: object) -> None:
        if "online" not in kwargs and kwargs.get("state") == "Active":
            kwargs["online"] = True
        super().__init__(**kwargs)


class DeviceCredential(Base):
    """Per-device MQTT credential record storing only the secret hash."""

    __tablename__ = "device_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id"), unique=True, nullable=False
    )
    mqtt_username: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Telemetry(Base):
    """Time-series water level, flow, and pump telemetry from ESP32 nodes."""

    __tablename__ = "telemetry"
    __table_args__ = (
        UniqueConstraint("device_id", "boot_id", "seq", name="uq_telemetry_dedupe"),
        Index("ix_telemetry_device_ts", "device_id", "ts"),
    )

    id: Mapped[int] = mapped_column(
        BIGINT_PK, primary_key=True, autoincrement=True
    )
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    boot_id: Mapped[str] = mapped_column(String(16), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ts: Mapped[datetime] = mapped_column(DT_MS, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DT_MS, nullable=False)
    distance_cm: Mapped[float] = mapped_column(Float, nullable=False)
    level_pct: Mapped[float] = mapped_column(Float, nullable=False)
    flow_lpm: Mapped[float] = mapped_column(Float, nullable=False)
    flow_total_l: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    pump_on: Mapped[bool] = mapped_column(Boolean, nullable=False)
    fault: Mapped[str] = mapped_column(String(64), default="")
    rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Command(Base):
    """Pump control command sent to a device with acknowledgement tracking."""

    __tablename__ = "commands"
    __table_args__ = (Index("ix_commands_device_sent", "device_id", "sent_at"),)

    id: Mapped[int] = mapped_column(
        BIGINT_PK, primary_key=True, autoincrement=True
    )
    cmd_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # sent | ok | fail | timeout
    sent_at: Mapped[datetime] = mapped_column(DT_MS, nullable=False)
    acked_at: Mapped[datetime | None] = mapped_column(DT_MS, nullable=True)
    reason: Mapped[str] = mapped_column(String(255), default="")


class DeviceConfig(Base):
    """Versioned key-value configuration parameters for a device."""

    __tablename__ = "device_configs"
    __table_args__ = (
        UniqueConstraint("device_id", "key", name="uq_device_config_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AlertRule(Base):
    """Configurable alert rule per device and alert type."""

    __tablename__ = "alert_rules"
    __table_args__ = (
        UniqueConstraint("device_id", "type", name="uq_alert_rule_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    severity: Mapped[str] = mapped_column(String(16), default="warning")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    """Active or historical alert instance triggered by the alert engine."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_device_state", "device_id", "state"),
        Index("ix_alerts_opened", "opened_at"),
    )

    id: Mapped[int] = mapped_column(
        BIGINT_PK, primary_key=True, autoincrement=True
    )
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("alert_rules.id"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    state: Mapped[str] = mapped_column(String(8), nullable=False)  # open | ack | closed
    opened_at: Mapped[datetime] = mapped_column(DT_MS, nullable=False)
    acked_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    acked_at: Mapped[datetime | None] = mapped_column(DT_MS, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DT_MS, nullable=True)
