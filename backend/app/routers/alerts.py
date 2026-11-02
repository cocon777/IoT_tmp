"""Real Alerts and Alert Rules router (TV2 + TV3 RBAC)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import alerts as engine
from app import lifecycle
from app.audit import write_audit
from app.db import get_db, utcnow
from app.events import emit
from app.lifecycle import Conflict, NotFound
from app.models.device import Alert, Device
from app.models.user import User, UserDevice
from app.security.lockout import get_client_ip
from app.security.rbac import (
    PERMISSION_MATRIX,
    can_access_device,
    require_device_access,
    require_role,
)

router = APIRouter(prefix="/api", tags=["alerts"])

State = Literal["open", "ack", "closed"]
RuleType = Literal[
    "LOW_LEVEL", "HIGH_LEVEL", "LEAK_SUSPECT", "PUMP_NO_FLOW", "DEVICE_OFFLINE"
]


class AlertOut(BaseModel):
    """Public representation of an Alert record."""

    id: int
    device_id: int
    device_code: str
    device_name: str
    type: str
    severity: str
    value: float
    state: State
    opened_at: datetime
    acked_by: str | None
    acked_at: datetime | None
    closed_at: datetime | None


class AlertPage(BaseModel):
    """Paginated alert list response."""

    total: int
    items: list[AlertOut]


class RuleOut(BaseModel):
    """Alert rule configuration for a device."""

    type: str
    enabled: bool
    severity: str
    params: dict[str, Any]


class RuleUpdate(BaseModel):
    """Single alert rule update item."""

    type: RuleType
    enabled: bool | None = None
    severity: Literal["warning", "critical"] | None = None
    params: dict[str, float] | None = None


class RulesUpdateIn(BaseModel):
    """Batch alert rules update payload."""

    rules: list[RuleUpdate] = Field(min_length=1, max_length=5)


def _utc(dt: datetime | None) -> datetime | None:
    return None if dt is None else dt.replace(tzinfo=timezone.utc)


def _out(a: Alert, dev: Device, acked_by_email: str | None) -> AlertOut:
    return AlertOut(
        id=a.id,
        device_id=a.device_id,
        device_code=dev.device_code,
        device_name=dev.name or "",
        type=a.type,
        severity=a.severity,
        value=a.value,
        state=a.state,  # type: ignore[arg-type]
        opened_at=_utc(a.opened_at),  # type: ignore[arg-type]
        acked_by=acked_by_email,
        acked_at=_utc(a.acked_at),
        closed_at=_utc(a.closed_at),
    )


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    state: State | None = None,
    device_id: int | None = None,
    type: RuleType | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["alerts:view"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> AlertPage:
    """List alerts across devices within the user's assigned scope."""
    conds = []
    if (current_user.role or "").lower() != "admin":
        conds.append(
            Alert.device_id.in_(
                select(UserDevice.device_id).where(
                    UserDevice.user_id == current_user.id
                )
            )
        )
    if state:
        conds.append(Alert.state == state)
    if device_id is not None:
        conds.append(Alert.device_id == device_id)
    if type:
        conds.append(Alert.type == type)
    total = (
        db.scalar(select(func.count()).select_from(Alert).where(*conds)) or 0
    )
    rows = db.execute(
        select(Alert, Device, User.email)
        .join(Device, Device.id == Alert.device_id)
        .outerjoin(User, User.id == Alert.acked_by)
        .where(*conds)
        .order_by(Alert.opened_at.desc(), Alert.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AlertPage(
        total=total, items=[_out(a, d, email) for a, d, email in rows]
    )


@router.get(
    "/devices/{device_id}/alerts",
    response_model=AlertPage,
    dependencies=[
        Depends(require_role(*PERMISSION_MATRIX["alerts:view"].allowed_roles)),
        Depends(require_device_access),
    ],
)
def list_device_alerts(
    device_id: int,
    state: State | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> AlertPage:
    """List alerts for a specific `device_id` within the user's assigned scope."""
    dev = lifecycle.get_device(db, device_id)
    conds = [Alert.device_id == dev.id]
    if state:
        conds.append(Alert.state == state)
    total = (
        db.scalar(select(func.count()).select_from(Alert).where(*conds)) or 0
    )
    rows = db.execute(
        select(Alert, Device, User.email)
        .join(Device, Device.id == Alert.device_id)
        .outerjoin(User, User.id == Alert.acked_by)
        .where(*conds)
        .order_by(Alert.opened_at.desc(), Alert.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AlertPage(
        total=total, items=[_out(a, d, email) for a, d, email in rows]
    )


def _load(
    db: Session, current_user: User, alert_id: int
) -> tuple[Alert, Device]:
    a = db.get(Alert, alert_id)
    if a is None or not can_access_device(current_user, a.device_id, db=db):
        raise NotFound("Không tìm thấy cảnh báo")
    dev = lifecycle.get_device(db, a.device_id)
    return a, dev


def _transition(
    db: Session,
    current_user: User,
    ip: str,
    alert_id: int,
    from_states: tuple[str, ...],
    values: dict[str, Any],
    action: str,
) -> AlertOut:
    a, dev = _load(db, current_user, alert_id)
    res = db.execute(
        update(Alert)
        .where(Alert.id == a.id, Alert.state.in_(from_states))
        .values(**values)
    )
    if res.rowcount != 1:
        db.rollback()
        raise Conflict(
            f"Cảnh báo đang ở trạng thái {a.state}, không thể thực hiện thao tác này"
        )
    write_audit(
        db,
        current_user.id,
        action,
        "alert",
        a.id,
        ip,
        f"device={dev.device_code} type={a.type}",
    )
    db.commit()
    db.refresh(a)
    emit("alert", engine.alert_event(a, dev))
    email = (
        db.scalar(select(User.email).where(User.id == a.acked_by))
        if a.acked_by
        else None
    )
    return _out(a, dev, email)


@router.post("/alerts/{alert_id}/ack", response_model=AlertOut)
def ack_alert(
    alert_id: int,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["alerts:ack_close"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> AlertOut:
    """Acknowledge an open alert (`open` -> `ack`)."""
    return _transition(
        db,
        current_user,
        get_client_ip(request),
        alert_id,
        ("open",),
        {"state": "ack", "acked_by": current_user.id, "acked_at": utcnow()},
        "alert.ack",
    )


@router.post("/alerts/{alert_id}/close", response_model=AlertOut)
def close_alert(
    alert_id: int,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["alerts:ack_close"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> AlertOut:
    """Manually close an open or acknowledged alert (`open`/`ack` -> `closed`)."""
    return _transition(
        db,
        current_user,
        get_client_ip(request),
        alert_id,
        ("open", "ack"),
        {"state": "closed", "closed_at": utcnow()},
        "alert.close",
    )


@router.post(
    "/devices/{device_id}/alerts/ack",
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["alerts:ack_close"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def ack_device_alerts(
    device_id: int,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["alerts:ack_close"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Acknowledge open alerts for `device_id` (Admin and assigned Operator)."""
    dev = lifecycle.get_device(db, device_id)
    now = utcnow()
    open_alerts = db.scalars(
        select(Alert).where(Alert.device_id == dev.id, Alert.state == "open")
    ).all()
    for a in open_alerts:
        a.state = "ack"
        a.acked_by = current_user.id
        a.acked_at = now
    write_audit(
        db,
        current_user.id,
        "alert.ack",
        "device",
        dev.id,
        get_client_ip(request),
        f"device={dev.device_code} acked={len(open_alerts)}",
    )
    db.commit()
    return {
        "device_id": dev.id,
        "state": "ack",
        "acked_count": len(open_alerts),
    }


def _rules_out(rules: dict[str, engine.RuleView]) -> list[RuleOut]:
    return [
        RuleOut(
            type=t,
            enabled=rules[t].enabled,
            severity=rules[t].severity,
            params=rules[t].params,
        )
        for t in engine.ALERT_TYPES
        if t in rules
    ]


@router.get(
    "/devices/{device_id}/alert-rules",
    response_model=list[RuleOut],
    dependencies=[
        Depends(require_role(*PERMISSION_MATRIX["alerts:view"].allowed_roles)),
        Depends(require_device_access),
    ],
)
def get_rules(
    device_id: int,
    db: Session = Depends(get_db),
) -> list[RuleOut]:
    """List alert rules for `device_id` (initializing defaults if needed)."""
    dev = lifecycle.get_device(db, device_id)
    rules = engine.load_rules(db, dev.id)
    db.commit()
    return _rules_out(rules)


@router.put(
    "/devices/{device_id}/alert-rules",
    response_model=list[RuleOut],
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def put_rules(
    device_id: int,
    body: RulesUpdateIn,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> list[RuleOut]:
    """Update alert rules for `device_id` (Admin and assigned Operator)."""
    dev = lifecycle.get_device(db, device_id)
    updates = [u.model_dump(exclude_none=True) for u in body.rules]
    return _rules_out(
        engine.apply_rule_updates(
            db,
            dev,
            updates,
            actor_id=current_user.id,
            ip=get_client_ip(request),
        )
    )
