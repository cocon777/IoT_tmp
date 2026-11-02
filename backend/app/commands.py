"""Pump control command lifecycle: send -> publish QoS 1 -> receive ACK or timeout (TV2 + TV3)."""

from datetime import timedelta
import json
import logging
import threading
from typing import Any, Protocol
import uuid

from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.config import settings
from app.db import session_scope, utcnow
from app.device_params import get_config
from app.errors import InvalidInput, PublishError
from app.events import emit
from app.lifecycle import Conflict
from app.models.device import Command, Device
from app.schemas import AckIn

log = logging.getLogger("commands")

ACK_STATES = {"Active", "Offline", "Fault"}


class Publisher(Protocol):
    """Protocol for MQTT command/config publishers."""

    def publish(
        self, topic: str, payload: str, qos: int = 1, retain: bool = False
    ) -> None: ...


def _iso(dt: Any) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def send_pump_command(
    s: Session,
    publisher: Publisher,
    dev: Device,
    *,
    value: str,
    duration_s: int | None,
    actor_id: int | None,
    ip: str,
    source: str | None = None,
) -> Command:
    """Validate device state, persist `sent` Command, audit, and publish QoS 1 MQTT command."""
    allowed = {"Active"} if value == "on" else {"Active", "Fault"}
    if dev.state not in allowed:
        raise Conflict(f"Thiết bị đang ở trạng thái {dev.state}, không nhận lệnh bơm")
    if not dev.online:
        raise Conflict("Thiết bị đang offline, không nhận lệnh bơm")
    if value == "on":
        max_s = min(
            settings.pump_max_duration_s,
            int(get_config(s, dev.id)["pump_max_run_s"]),
        )
        duration_s = duration_s or min(settings.pump_default_duration_s, max_s)
        if duration_s > max_s:
            raise InvalidInput(
                f"Thời gian bơm tối đa {max_s} giây (giới hạn cấu hình của thiết bị)"
            )
    else:
        duration_s = None

    if (
        value == "on"
        and s.scalars(
            select(Command.id).where(
                Command.device_id == dev.id, Command.status == "sent"
            )
        ).first()
    ):
        raise Conflict("Đang chờ phản hồi của lệnh trước, thử lại sau vài giây")

    now = utcnow()
    cmd_id = str(uuid.uuid4())
    params = {
        "value": value,
        **({"duration_s": duration_s} if duration_s else {}),
        **({"source": source} if source else {}),
    }
    cmd = Command(
        cmd_id=cmd_id,
        device_id=dev.id,
        user_id=actor_id,
        action="pump",
        params_json=json.dumps(params),
        status="sent",
        sent_at=now,
        reason="",
    )
    s.add(cmd)
    write_audit(
        s,
        actor_id,
        "command.send",
        "device",
        dev.id,
        ip,
        f"cmd={cmd_id} pump {json.dumps(params)}",
    )
    s.commit()

    payload = {
        "cmd_id": cmd_id,
        "action": "pump",
        "value": value,
        **({"duration_s": duration_s} if duration_s else {}),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        publisher.publish(f"wms/{dev.device_code}/cmd", json.dumps(payload), qos=1)
    except PublishError as e:
        s.execute(
            update(Command)
            .where(Command.id == cmd.id, Command.status == "sent")
            .values(status="fail", reason=str(e)[:200])
        )
        write_audit(
            s,
            actor_id,
            "command.publish_failed",
            "device",
            dev.id,
            ip,
            f"cmd={cmd_id}",
        )
        s.commit()
        raise
    return cmd


def _result_event(
    dev: Device, cmd_id: str, status: str, reason: str, acked_at: Any
) -> dict[str, Any]:
    return {
        "device_code": dev.device_code,
        "device_id": dev.id,
        "cmd_id": cmd_id,
        "status": status,
        "reason": reason,
        "acked_at": _iso(acked_at),
    }


def handle_ack(device_code: str, data: dict[str, Any]) -> None:
    """Process incoming `wms/{deviceId}/ack` payload and update Command status."""
    try:
        msg = AckIn.model_validate(data)
    except ValidationError as e:
        log.warning(
            "reject ack device=%s invalid=%s",
            device_code,
            [(".".join(map(str, x["loc"])), x["msg"]) for x in e.errors()][:5],
        )
        return

    now = utcnow()
    with session_scope() as s:
        dev = s.scalars(
            select(Device).where(Device.device_code == device_code)
        ).first()
        if dev is None or dev.state not in ACK_STATES:
            log.warning(
                "reject ack device=%s: unknown or state=%s",
                device_code,
                dev.state if dev else None,
            )
            return
        cmd = s.scalars(
            select(Command).where(Command.cmd_id == msg.cmd_id)
        ).first()
        if cmd is None or cmd.device_id != dev.id:
            log.warning(
                "reject ack device=%s: cmd_id không thuộc thiết bị này",
                device_code,
            )
            return

        reason = msg.reason or ""
        if cmd.status == "timeout":
            reason = (reason + " (ack muộn)").strip()
        res = s.execute(
            update(Command)
            .where(Command.id == cmd.id, Command.status.in_(("sent", "timeout")))
            .values(status=msg.result, acked_at=now, reason=reason)
        )
        if res.rowcount != 1:
            log.info("duplicate ack device=%s cmd=%s", device_code, msg.cmd_id)
            return
        write_audit(
            s,
            None,
            "command.ack",
            "command",
            msg.cmd_id,
            "",
            f"device={device_code} result={msg.result} reason={reason}",
        )
        event = _result_event(dev, msg.cmd_id, msg.result, reason, now)
    emit("command_result", event)


def mark_timed_out() -> int:
    """Mark pending `sent` commands older than `command_timeout_s` as `timeout`."""
    cutoff = utcnow() - timedelta(seconds=settings.command_timeout_s)
    events = []
    with session_scope() as s:
        rows = s.execute(
            select(Command.id, Command.cmd_id, Command.device_id).where(
                Command.status == "sent", Command.sent_at < cutoff
            )
        ).all()
        for row_id, cmd_id, device_id in rows:
            res = s.execute(
                update(Command)
                .where(Command.id == row_id, Command.status == "sent")
                .values(status="timeout", reason="Không nhận được ack")
            )
            if res.rowcount == 1:
                write_audit(
                    s,
                    None,
                    "command.timeout",
                    "command",
                    cmd_id,
                    "",
                    f"device_id={device_id}",
                )
                dev = s.get(Device, device_id)
                if dev is not None:
                    events.append(
                        _result_event(
                            dev, cmd_id, "timeout", "Không nhận được ack", utcnow()
                        )
                    )
    for ev in events:
        log.warning("command timeout device=%s cmd=%s", ev["device_code"], ev["cmd_id"])
        emit("command_result", ev)
    return len(events)


def run_command_watcher(stop: threading.Event, interval_s: float = 1.0) -> None:
    """Background worker checking for timed-out pump commands."""
    while not stop.wait(interval_s):
        try:
            mark_timed_out()
        except Exception:
            log.exception("command watcher error")
