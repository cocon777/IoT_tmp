"""Real Device management & lifecycle router (TV2 + TV3 RBAC)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import lifecycle
from app.broker_admin import BrokerAdmin, get_broker_admin
from app.db import get_db
from app.models.device import Device
from app.models.user import User, UserDevice
from app.security.lockout import get_client_ip
from app.security.rbac import (
    PERMISSION_MATRIX,
    require_device_access,
    require_role,
)

router = APIRouter(prefix="/api/devices", tags=["devices"])


class DeviceCreate(BaseModel):
    """Request payload for registering a new IoT device."""

    device_code: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    name: str = Field(default="", max_length=128)
    hw_version: str = Field(default="", max_length=32)


class DeviceOut(BaseModel):
    """Public representation of a Device record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    device_code: str
    name: str | None = ""
    state: str
    hw_version: str = ""
    fw_version: str = ""
    online: bool = False
    last_seen: datetime | None = None
    created_at: datetime | None = None


class ProvisionOut(BaseModel):
    """One-time MQTT credentials returned when provisioning a device."""

    device: DeviceOut
    mqtt_username: str
    mqtt_password: str
    note: str = "Mật khẩu chỉ hiển thị một lần này; hệ thống chỉ lưu bản băm."


class StateChange(BaseModel):
    """Request payload for changing a device's lifecycle state."""

    state: Literal["Active", "Maintenance", "Decommissioned"]
    confirm: bool = False


@router.get("", response_model=list[DeviceOut])
def list_devices(
    state: str | None = None,
    q: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:view"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> list[Device]:
    """List devices visible to the current user (Admin sees all; Operator/Viewer see assigned)."""
    stmt = select(Device).order_by(Device.id).limit(limit)
    if (current_user.role or "").lower() != "admin":
        stmt = stmt.where(
            Device.id.in_(
                select(UserDevice.device_id).where(
                    UserDevice.user_id == current_user.id
                )
            )
        )
    if state:
        stmt = stmt.where(Device.state == state)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(Device.device_code.like(like), Device.name.like(like))
        )
    return list(db.scalars(stmt).all())


@router.post("", response_model=DeviceOut)
def create_device(
    body: DeviceCreate,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:lifecycle_admin"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> Device:
    """Register a new device in `Registered` state (Admin only)."""
    return lifecycle.create_device(
        db,
        device_code=body.device_code,
        name=body.name,
        hw_version=body.hw_version,
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )


@router.get(
    "/{device_id}",
    response_model=DeviceOut,
    dependencies=[
        Depends(require_role(*PERMISSION_MATRIX["devices:view"].allowed_roles)),
        Depends(require_device_access),
    ],
)
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
) -> Device:
    """Get details of a single device within the user's scope."""
    return lifecycle.get_device(db, device_id)


@router.post("/{device_id}/provision", response_model=ProvisionOut)
def provision_device(
    device_id: int,
    request: Request,
    response: Response,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:lifecycle_admin"].allowed_roles)
    ),
    broker: BrokerAdmin = Depends(get_broker_admin),
    db: Session = Depends(get_db),
) -> ProvisionOut:
    """Provision MQTT credentials for a device and return password once (Admin only)."""
    dev, secret = lifecycle.provision(
        db,
        broker,
        device_id,
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )
    response.headers["Cache-Control"] = "no-store"
    return ProvisionOut(
        device=DeviceOut.model_validate(dev),
        mqtt_username=dev.device_code,
        mqtt_password=secret,
    )


@router.patch(
    "/{device_id}/state",
    response_model=DeviceOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:set_maintenance"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def change_state(
    device_id: int,
    body: StateChange,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:set_maintenance"].allowed_roles)
    ),
    broker: BrokerAdmin = Depends(get_broker_admin),
    db: Session = Depends(get_db),
) -> Device:
    """Change device lifecycle state (`Active`, `Maintenance`, or `Decommissioned`)."""
    if (current_user.role or "").lower() == "operator" and body.state != "Maintenance":
        raise HTTPException(
            status_code=403,
            detail="Operator chỉ được chuyển thiết bị của mình sang Maintenance",
        )
    if body.state == "Decommissioned" and not body.confirm:
        raise HTTPException(
            status_code=422,
            detail="Thu hồi là không thể hoàn tác: gửi confirm=true để xác nhận",
        )
    return lifecycle.change_state(
        db,
        broker,
        device_id,
        body.state,
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )


@router.patch(
    "/{device_id}/maintenance",
    response_model=DeviceOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:set_maintenance"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def set_device_maintenance(
    device_id: int,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:set_maintenance"].allowed_roles)
    ),
    broker: BrokerAdmin = Depends(get_broker_admin),
    db: Session = Depends(get_db),
) -> Device:
    """Transition a device into `Maintenance` state (Admin and assigned Operator)."""
    dev = lifecycle.get_device(db, device_id)
    if dev.state == "Maintenance":
        return dev
    return lifecycle.change_state(
        db,
        broker,
        device_id,
        "Maintenance",
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )
