"""MQTT ingestion pipeline for telemetry, status, and command ACKs (TV2 + TV3 device_guard)."""

from collections import defaultdict, deque
from datetime import timedelta
import json
import logging
import threading
import time
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import alerts, commands
from app.config import settings
from app.db import session_scope, utcnow
from app.events import emit as _emit
from app.events import set_event_callback  # noqa: F401
from app.models.device import Device, Telemetry
from app.schemas import StatusIn, TelemetryIn
from app.security.device_guard import check_payload_size, validate_telemetry_payload

log = logging.getLogger("ingest")

INGEST_STATES = {"Active", "Offline", "Fault"}
STATUS_STATES = {"Provisioned", "Active", "Offline", "Fault"}

_rate: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()


def _rate_limited(device_code: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        dq = _rate[device_code]
        while dq and now - dq[0] > settings.rate_limit_window_s:
            dq.popleft()
        if len(dq) >= settings.rate_limit_msgs:
            return True
        dq.append(now)
        return False


def handle_message(topic: str, payload: bytes, retained: bool = False) -> None:
    """Entrypoint for incoming MQTT messages on `wms/+/{telemetry|status|ack}`."""
    parts = topic.split("/")
    if len(parts) != 3 or parts[0] != "wms":
        log.warning("unexpected topic: %s", topic[:100])
        return
    _, device_code, kind = parts

    if not check_payload_size(payload, max_bytes=settings.max_payload_bytes):
        log.warning("payload too large device=%s size=%d", device_code, len(payload))
        return
    if _rate_limited(device_code):
        log.warning("rate limited device=%s", device_code)
        return
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        log.warning("invalid JSON device=%s topic=%s", device_code, kind)
        return
    if not isinstance(data, dict):
        log.warning("payload is not an object device=%s", device_code)
        return

    if kind == "telemetry":
        ok_guard, reason_guard = validate_telemetry_payload(payload)
        if not ok_guard:
            log.warning(
                "device_guard rejected telemetry device=%s reason=%s",
                device_code,
                reason_guard,
            )
            return
        _handle_telemetry(device_code, data)
    elif kind == "status":
        _handle_status(device_code, data, retained)
    elif kind == "ack":
        commands.handle_ack(device_code, data)
    else:
        log.debug("ignored topic kind=%s device=%s", kind, device_code)


def _handle_telemetry(device_code: str, data: dict[str, Any]) -> None:
    try:
        msg = TelemetryIn.model_validate(data)
    except ValidationError as e:
        problems = [(".".join(map(str, x["loc"])), x["msg"]) for x in e.errors()][:5]
        log.warning("reject telemetry device=%s invalid=%s", device_code, problems)
        return

    if str(msg.device_id) != device_code:
        log.warning(
            "reject telemetry: device_id mismatch topic=%s payload=%s",
            device_code,
            str(msg.device_id)[:64],
        )
        return

    now = utcnow()
    if abs((now - msg.ts).total_seconds()) > settings.ts_tolerance_s:
        log.warning(
            "reject telemetry device=%s: ts out of tolerance (%s)",
            device_code,
            msg.ts,
        )
        return

    with session_scope() as s:
        dev = s.scalars(
            select(Device).where(Device.device_code == device_code)
        ).first()
        if dev is None or dev.state not in INGEST_STATES:
            log.warning(
                "reject telemetry device=%s: unknown or state=%s",
                device_code,
                dev.state if dev else None,
            )
            return

        row = Telemetry(
            device_id=dev.id,
            boot_id=msg.boot_id,
            seq=msg.seq,
            ts=msg.ts,
            received_at=now,
            distance_cm=msg.distance_cm,
            level_pct=msg.level_pct,
            flow_lpm=msg.flow_lpm,
            flow_total_l=msg.flow_total_l,
            pump_on=msg.pump_on,
            fault=msg.fault,
            rssi=msg.rssi,
        )
        try:
            with s.begin_nested():
                s.add(row)
        except IntegrityError:
            log.info(
                "duplicate telemetry device=%s boot=%s seq=%d",
                device_code,
                msg.boot_id,
                msg.seq,
            )
            return

        was_offline = dev.state == "Offline" or not dev.online
        dev.last_seen = now
        dev.online = True
        if dev.state == "Offline":
            dev.state = "Active"

        event = {
            "device_code": device_code,
            "device_id": dev.id,
            "state": dev.state,
            "ts": msg.ts.isoformat() + "Z",
            "received_at": now.isoformat() + "Z",
            "level_pct": msg.level_pct,
            "flow_lpm": msg.flow_lpm,
            "flow_total_l": msg.flow_total_l,
            "pump_on": msg.pump_on,
            "fault": msg.fault,
        }

    if was_offline:
        alerts.on_device_online(event["device_id"])
    alerts.evaluate(
        alerts.Sample(
            device_id=event["device_id"],
            ts=msg.ts,
            level_pct=msg.level_pct,
            flow_lpm=msg.flow_lpm,
            pump_on=msg.pump_on,
        )
    )
    _emit("telemetry", event)


def _handle_status(
    device_code: str, data: dict[str, Any], retained: bool
) -> None:
    try:
        msg = StatusIn.model_validate(data)
    except ValidationError as e:
        log.warning(
            "reject status device=%s invalid=%s",
            device_code,
            [(".".join(map(str, x["loc"])), x["msg"]) for x in e.errors()][:5],
        )
        return

    if retained and msg.status == "online":
        return

    now = utcnow()
    with session_scope() as s:
        dev = s.scalars(
            select(Device).where(Device.device_code == device_code)
        ).first()
        if dev is None or dev.state not in STATUS_STATES:
            log.warning(
                "reject status device=%s: unknown or state=%s",
                device_code,
                dev.state if dev else None,
            )
            return

        was_offline = dev.state == "Offline" or not dev.online
        applied_event = None
        if msg.status == "online":
            dev.online = True
            dev.last_seen = now
            if msg.fw_version:
                dev.fw_version = msg.fw_version
            if (
                msg.config_version is not None
                and dev.config_applied_version != msg.config_version
            ):
                dev.config_applied_version = msg.config_version
                applied_event = {
                    "device_code": device_code,
                    "device_id": dev.id,
                    "applied_version": msg.config_version,
                }
            if dev.state in ("Provisioned", "Offline"):
                dev.state = "Active"
            if msg.free_heap is not None:
                log.info("heartbeat device=%s free_heap=%d", device_code, msg.free_heap)
        else:
            dev.online = False
            if dev.state == "Active":
                dev.state = "Offline"

        event = {
            "device_code": device_code,
            "device_id": dev.id,
            "state": dev.state,
            "online": dev.online,
            "fw_version": dev.fw_version,
        }

    _emit("device_state", event)
    if applied_event:
        _emit("config_applied", applied_event)
    if msg.status == "online":
        if was_offline:
            alerts.on_device_online(event["device_id"])
    else:
        alerts.on_device_offline(event["device_id"])


def mark_stale_offline() -> int:
    """Mark online devices whose `last_seen` exceeded `heartbeat_timeout_s` as `Offline`."""
    cutoff = utcnow() - timedelta(seconds=settings.heartbeat_timeout_s)
    events = []
    with session_scope() as s:
        stale = s.scalars(
            select(Device).where(
                Device.online.is_(True), Device.last_seen < cutoff
            )
        ).all()
        for dev in stale:
            dev.online = False
            if dev.state == "Active":
                dev.state = "Offline"
            events.append(
                {
                    "device_code": dev.device_code,
                    "device_id": dev.id,
                    "state": dev.state,
                    "online": False,
                    "fw_version": dev.fw_version,
                }
            )
    for ev in events:
        log.warning("heartbeat timeout device=%s", ev["device_code"])
        _emit("device_state", ev)
        alerts.on_device_offline(ev["device_id"])
    return len(events)


def run_offline_watcher(stop: threading.Event, interval_s: float = 10.0) -> None:
    """Background worker checking for stale device heartbeats."""
    while not stop.wait(interval_s):
        try:
            mark_stale_offline()
        except Exception:
            log.exception("offline watcher error")
