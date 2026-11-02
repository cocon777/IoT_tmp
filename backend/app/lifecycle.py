"""Device lifecycle management: Registered -> Provisioned -> Active -> ... -> Decommissioned (TV2 + TV3)."""

import hashlib
import logging
import secrets

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.broker_admin import BrokerAdmin, BrokerError
from app.db import utcnow
from app.events import emit
from app.models.device import Device, DeviceCredential
from app.models.user import User

log = logging.getLogger("lifecycle")

TRANSITIONS: dict[str, set[str]] = {
    "Registered": {"Provisioned"},
    "Provisioned": {"Active", "Decommissioned"},
    "Active": {"Offline", "Fault", "Maintenance", "Decommissioned"},
    "Offline": {"Active", "Decommissioned"},
    "Fault": {"Maintenance"},
    "Maintenance": {"Active", "Decommissioned"},
    "Decommissioned": set(),
}
MANUAL_TARGETS = {"Active", "Maintenance", "Decommissioned"}


class LifecycleError(Exception):
    """Base class for device lifecycle errors."""


class NotFound(LifecycleError):
    """Raised when a target resource does not exist or is out of user scope (HTTP 404)."""


class Conflict(LifecycleError):
    """Raised on duplicate device code or invalid state for an operation (HTTP 409)."""


class InvalidTransition(LifecycleError):
    """Raised when a requested device state transition is not permitted (HTTP 409)."""

    def __init__(self, current: str, target: str) -> None:
        super().__init__(f"Không thể chuyển {current} -> {target}")
        self.current, self.target = current, target


def can_transition(current: str, target: str) -> bool:
    """Return True if transitioning from `current` to `target` is valid."""
    return target in TRANSITIONS.get(current, set())


def hash_secret(secret: str) -> str:
    """Return SHA-256 hex digest of a generated high-entropy MQTT secret."""
    return hashlib.sha256(secret.encode()).hexdigest()


def _resolve_actor_id(s: Session, actor_id: int | None) -> int | None:
    """Ensure actor_id exists in `users` table before writing foreign-key audit log."""
    if actor_id is None:
        return None
    return actor_id if s.get(User, actor_id) is not None else None


def _announce(dev: Device) -> None:
    """Broadcast device lifecycle state change to WebSocket clients."""
    emit(
        "device_state",
        {
            "device_code": dev.device_code,
            "device_id": dev.id,
            "state": dev.state,
            "online": dev.online,
            "fw_version": dev.fw_version,
        },
    )


def get_device(s: Session, device_id: int) -> Device:
    """Fetch Device by primary key or raise NotFound (404)."""
    dev = s.get(Device, device_id)
    if dev is None:
        raise NotFound("Device not found")
    return dev


def create_device(
    s: Session,
    *,
    device_code: str,
    name: str,
    hw_version: str,
    actor_id: int | None,
    ip: str,
) -> Device:
    """Register a new device in `Registered` state and record an audit log entry."""
    if s.scalars(select(Device).where(Device.device_code == device_code)).first():
        raise Conflict(f"Mã thiết bị '{device_code}' đã tồn tại")
    dev = Device(
        device_code=device_code,
        name=name,
        hw_version=hw_version,
        state="Registered",
        online=False,
    )
    s.add(dev)
    try:
        s.flush()
        write_audit(
            s,
            _resolve_actor_id(s, actor_id),
            "device.create",
            "device",
            dev.id,
            ip,
            f"code={device_code}",
        )
        s.commit()
    except IntegrityError as exc:
        s.rollback()
        raise Conflict(f"Mã thiết bị '{device_code}' đã tồn tại") from exc
    _announce(dev)
    return dev


def provision(
    s: Session,
    broker: BrokerAdmin,
    device_id: int,
    *,
    actor_id: int | None,
    ip: str,
) -> tuple[Device, str]:
    """Provision MQTT credentials for a device (`Registered` -> `Provisioned`).

    Returns `(device, plaintext_secret)` once and stores only the hash in DB.
    """
    dev = get_device(s, device_id)
    existing_cred = s.scalars(
        select(DeviceCredential).where(DeviceCredential.device_id == dev.id)
    ).first()
    if existing_cred is not None or dev.state not in ("Registered", "Active"):
        raise InvalidTransition(dev.state, "Provisioned")

    code = dev.device_code
    secret = secrets.token_urlsafe(24)

    broker.create_client(code, secret)
    try:
        s.add(
            DeviceCredential(
                device_id=dev.id,
                mqtt_username=code,
                secret_hash=hash_secret(secret),
            )
        )
        if dev.state == "Registered":
            dev.state = "Provisioned"
        write_audit(
            s,
            _resolve_actor_id(s, actor_id),
            "device.provision",
            "device",
            dev.id,
            ip,
            f"username={code}",
        )
        s.commit()
    except Exception:
        s.rollback()
        try:
            broker.delete_client(code)
        except BrokerError:
            log.exception("không xóa được tài khoản mồ côi %s trên broker", code)
        raise
    _announce(dev)
    return dev, secret


def change_state(
    s: Session,
    broker: BrokerAdmin,
    device_id: int,
    target: str,
    *,
    actor_id: int | None,
    ip: str,
) -> Device:
    """Transition a device to a manual target state (`Active`, `Maintenance`, `Decommissioned`)."""
    dev = get_device(s, device_id)
    current, code = dev.state, dev.device_code
    if target not in MANUAL_TARGETS or not can_transition(current, target):
        raise InvalidTransition(current, target)

    if target == "Maintenance":
        broker.set_enabled(code, False)
        dev.online = False
    elif target == "Active" and current == "Maintenance":
        broker.set_enabled(code, True)
    elif target == "Decommissioned":
        broker.delete_client(code)
        dev.online = False
        cred = s.scalars(
            select(DeviceCredential).where(DeviceCredential.device_id == dev.id)
        ).first()
        if cred and cred.revoked_at is None:
            cred.revoked_at = utcnow()

    dev.state = target
    write_audit(
        s,
        _resolve_actor_id(s, actor_id),
        "device.state",
        "device",
        dev.id,
        ip,
        f"{current}->{target}",
    )
    try:
        s.commit()
    except Exception:
        s.rollback()
        log.exception(
            "commit thất bại sau khi đã đổi broker (device=%s %s->%s): cần đối soát",
            code,
            current,
            target,
        )
        raise
    _announce(dev)
    return dev
