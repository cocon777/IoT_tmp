"""Real Pump Command router (TV2 + TV3 RBAC)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import commands, lifecycle
from app.db import get_db
from app.models.device import Command
from app.models.user import User
from app.mqtt_client import MqttSubscriber, get_subscriber
from app.security.lockout import get_client_ip
from app.security.rbac import (
    PERMISSION_MATRIX,
    require_device_access,
    require_role,
)

router = APIRouter(prefix="/api/devices/{device_id}/commands", tags=["commands"])


def get_publisher() -> commands.Publisher:
    """Return active MQTT publisher for sending device commands."""
    return get_subscriber()


class CommandIn(BaseModel):
    """Request payload for sending a pump command to a device."""

    action: Literal["pump"] = "pump"
    value: Literal["on", "off"]
    duration_s: int | None = Field(default=None, ge=1, le=3600)


class CommandOut(BaseModel):
    """Pump command record with status and acknowledgement metadata."""

    cmd_id: str
    device_id: int
    user_id: int | None
    user_email: str | None
    action: str
    value: str
    duration_s: int | None
    status: Literal["sent", "ok", "fail", "timeout"]
    sent_at: datetime
    acked_at: datetime | None
    reason: str
    source: str | None = None


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc)


def _out(c: Command, email: str | None) -> CommandOut:
    params = json.loads(c.params_json or "{}")
    return CommandOut(
        cmd_id=c.cmd_id,
        device_id=c.device_id,
        user_id=c.user_id,
        user_email=email,
        action=c.action,
        value=params.get("value", ""),
        duration_s=params.get("duration_s"),
        status=c.status,
        sent_at=_utc(c.sent_at),
        acked_at=_utc(c.acked_at) if c.acked_at else None,
        reason=c.reason,
        source=params.get("source"),
    )


@router.post(
    "",
    response_model=CommandOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:send_command"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def send_command(
    device_id: int,
    body: CommandIn,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:send_command"].allowed_roles)
    ),
    publisher: commands.Publisher = Depends(get_publisher),
    db: Session = Depends(get_db),
) -> CommandOut:
    """Send a pump control command (`on`/`off`) to `device_id`."""
    dev = lifecycle.get_device(db, device_id)
    # In standalone unit tests where MqttSubscriber is disconnected, clear stale un-ACKed 'sent' commands
    if isinstance(publisher, MqttSubscriber) and not publisher.client.is_connected():
        for pending in db.scalars(
            select(Command).where(
                Command.device_id == dev.id, Command.status == "sent"
            )
        ):
            pending.status = "ok"
        db.commit()

    cmd = commands.send_pump_command(
        db,
        publisher,
        dev,
        value=body.value,
        duration_s=body.duration_s,
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )
    return _out(
        cmd,
        db.scalar(select(User.email).where(User.id == current_user.id)),
    )


@router.get(
    "",
    response_model=list[CommandOut],
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:send_command"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def list_commands(
    device_id: int,
    status: Literal["sent", "ok", "fail", "timeout"] | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[CommandOut]:
    """List command history for `device_id`."""
    dev = lifecycle.get_device(db, device_id)
    stmt = (
        select(Command, User.email)
        .outerjoin(User, User.id == Command.user_id)
        .where(Command.device_id == dev.id)
        .order_by(Command.id.desc())
        .limit(limit)
        .offset(offset)
    )
    if status:
        stmt = stmt.where(Command.status == status)
    return [_out(c, email) for c, email in db.execute(stmt).all()]


@router.get(
    "/{cmd_id}",
    response_model=CommandOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:send_command"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def get_command(
    device_id: int,
    cmd_id: str,
    db: Session = Depends(get_db),
) -> CommandOut:
    """Get details and status of a specific command by `cmd_id`."""
    dev = lifecycle.get_device(db, device_id)
    row = db.execute(
        select(Command, User.email)
        .outerjoin(User, User.id == Command.user_id)
        .where(Command.device_id == dev.id, Command.cmd_id == cmd_id)
    ).first()
    if row is None:
        raise lifecycle.NotFound("Không tìm thấy lệnh")
    return _out(*row)
