"""Real Device Configuration router (TV2 + TV3 RBAC)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app import device_config, lifecycle
from app.db import get_db
from app.models.user import User
from app.routers.commands import get_publisher
from app.security.lockout import get_client_ip
from app.security.rbac import (
    PERMISSION_MATRIX,
    require_device_access,
    require_role,
)

router = APIRouter(prefix="/api/devices/{device_id}/config", tags=["config"])


class ConfigUpdate(BaseModel):
    """Partial configuration update payload."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: int | None = None
    sample_interval_s: int | None = None
    tank_height_cm: int | float | None = None
    low_pct: int | float | None = None
    high_pct: int | float | None = None
    pump_max_run_s: int | None = None
    auto_mode: bool | None = None
    dry_run_s: int | None = None


class LimitOut(BaseModel):
    """Parameter type and range bounds."""

    type: str
    min: float | None
    max: float | None


class ConfigOut(BaseModel):
    """Current device configuration state and synchronization status."""

    device_id: int
    version: int
    config: dict[str, Any]
    limits: dict[str, LimitOut]
    applied_version: int | None
    sync_status: Literal["default", "unknown", "applied", "pending", "mismatch"]
    updated_at: datetime | None
    updated_by: str | None


class ConfigChangeOut(ConfigOut):
    """Response after updating or republishing device configuration."""

    changed: list[str]
    delivery: Literal["published", "failed", "unchanged"]


def _fix(state: dict[str, Any]) -> dict[str, Any]:
    if state["updated_at"] is not None:
        state = {
            **state,
            "updated_at": state["updated_at"].replace(tzinfo=timezone.utc),
        }
    return state


@router.get(
    "",
    response_model=ConfigOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def get_config(
    device_id: int,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get current configuration, limits, and sync status for `device_id`."""
    return _fix(device_config.get_state(db, lifecycle.get_device(db, device_id)))


@router.put(
    "",
    response_model=ConfigChangeOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def put_config(
    device_id: int,
    body: ConfigUpdate,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
    ),
    publisher: Any = Depends(get_publisher),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Update configuration parameters (version + 1) and publish retained MQTT config."""
    dev = lifecycle.get_device(db, device_id)
    updates = body.model_dump(exclude_none=True, exclude={"version"})
    state, changed, delivery = device_config.update_config(
        db,
        publisher,
        dev,
        updates,
        expected_version=body.version,
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )
    return {**_fix(state), "changed": changed, "delivery": delivery}


@router.post(
    "/publish",
    response_model=ConfigChangeOut,
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def republish_config(
    device_id: int,
    request: Request,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:update_config"].allowed_roles)
    ),
    publisher: Any = Depends(get_publisher),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Re-publish current saved configuration (retained) to `device_id`."""
    dev = lifecycle.get_device(db, device_id)
    state, delivery = device_config.publish_current(
        db,
        publisher,
        dev,
        actor_id=current_user.id,
        ip=get_client_ip(request),
    )
    return {**_fix(state), "changed": [], "delivery": delivery}
