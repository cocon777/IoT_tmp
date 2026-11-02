"""User management and device assignment API endpoints (Admin only, S8)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.device_stub import DeviceStub
from app.models.user import User, UserDevice
from app.security.auth import hash_password, validate_password_strength
from app.security.lockout import get_client_ip
from app.security.rbac import PERMISSION_MATRIX, require_role
from app.services import audit

router = APIRouter(tags=["users"])

RoleType = Literal["admin", "operator", "viewer"]
StatusType = Literal["active", "locked", "disabled"]


class UserResponse(BaseModel):
    """Public representation of a user account (never exposes password_hash)."""

    id: int
    email: EmailStr
    full_name: str
    role: str
    status: str
    created_at: datetime
    assigned_device_ids: list[int] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class UserCreateRequest(BaseModel):
    """Request payload for creating a new user account."""

    email: EmailStr
    password: str
    full_name: str = Field(..., min_length=1, max_length=255)
    role: RoleType = "viewer"
    status: StatusType = "active"


class UserUpdateRequest(BaseModel):
    """Request payload for updating user role, status, or full_name."""

    role: RoleType | None = None
    status: StatusType | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=255)


def _to_user_response(db: Session, user: User) -> UserResponse:
    """Serialize User ORM object with assigned device IDs, excluding password_hash."""
    rows = (
        db.query(UserDevice.device_id)
        .filter(UserDevice.user_id == user.id)
        .order_by(UserDevice.device_id)
        .all()
    )
    device_ids = [r[0] for r in rows]
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        status=user.status,
        created_at=user.created_at,
        assigned_device_ids=device_ids,
    )


def _count_active_admins(db: Session) -> int:
    """Count how many active admin accounts currently exist in the database."""
    return (
        db.query(User)
        .filter(User.role == "admin", User.status == "active")
        .count()
    )


@router.get("/api/users", response_model=list[UserResponse])
def list_users(
    _admin: User = Depends(
        require_role(*PERMISSION_MATRIX["users:manage"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> list[UserResponse]:
    """List all users in the system (Admin only)."""
    users = db.query(User).order_by(User.id).all()
    return [_to_user_response(db, u) for u in users]


@router.post(
    "/api/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["users:manage"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Create a new user account with validated role and hashed password (Admin only)."""
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    validate_password_strength(payload.password)

    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        status=payload.status,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.log(
        db=db,
        user=current_admin,
        action="CREATE_USER",
        target_type="user",
        target_id=user.id,
        ip=get_client_ip(request),
        detail={"email": user.email, "role": user.role, "status": user.status},
    )
    return _to_user_response(db, user)


@router.patch("/api/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["users:manage"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Update a user's role, status, or full_name (Admin only).

    Prevents the last active Admin from locking/disabling or demoting themselves
    (or being demoted/locked if they are the sole remaining active Admin).
    """
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    old_role = target.role
    old_status = target.status
    new_role = payload.role if payload.role is not None else target.role
    new_status = payload.status if payload.status is not None else target.status

    # Prevent locking or demoting the last active Admin
    if target.role == "admin" and target.status == "active":
        losing_admin_privilege = new_role != "admin" or new_status != "active"
        if losing_admin_privilege and _count_active_admins(db) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot lock or demote the last active admin account",
            )

    if payload.role is not None:
        target.role = payload.role
    if payload.status is not None:
        target.status = payload.status
        if payload.status == "active":
            target.failed_attempts = 0
            target.locked_until = None
    if payload.full_name is not None:
        target.full_name = payload.full_name

    db.add(target)
    db.commit()
    db.refresh(target)

    client_ip = get_client_ip(request)
    if payload.role is not None and payload.role != old_role:
        audit.log(
            db=db,
            user=current_admin,
            action="CHANGE_USER_ROLE",
            target_type="user",
            target_id=target.id,
            ip=client_ip,
            detail={"old_role": old_role, "new_role": target.role},
        )
    if payload.status is not None and payload.status != old_status:
        action_name = "LOCK_USER" if target.status != "active" else "UNLOCK_USER"
        audit.log(
            db=db,
            user=current_admin,
            action=action_name,
            target_type="user",
            target_id=target.id,
            ip=client_ip,
            detail={"old_status": old_status, "new_status": target.status},
        )

    return _to_user_response(db, target)


@router.post("/api/users/{user_id}/devices/{device_id}", response_model=UserResponse)
def assign_device_to_user(
    user_id: int,
    device_id: int,
    request: Request,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:assign"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Assign a device to a user in `user_devices` (Admin only)."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    device = db.query(DeviceStub).filter(DeviceStub.id == device_id).first()
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    existing = (
        db.query(UserDevice)
        .filter(
            UserDevice.user_id == user_id,
            UserDevice.device_id == device_id,
        )
        .first()
    )
    if existing is None:
        db.add(UserDevice(user_id=user_id, device_id=device_id))
        db.commit()
        audit.log(
            db=db,
            user=current_admin,
            action="ASSIGN_DEVICE",
            target_type="device",
            target_id=device_id,
            ip=get_client_ip(request),
            detail={"user_id": user_id, "device_id": device_id},
        )

    return _to_user_response(db, target_user)
def unassign_device_from_user(
    user_id: int,
    device_id: int,
    request: Request,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:assign"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Remove a device assignment from a user in `user_devices` (Admin only)."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    existing = (
        db.query(UserDevice)
        .filter(
            UserDevice.user_id == user_id,
            UserDevice.device_id == device_id,
        )
        .first()
    )
    if existing is not None:
        db.delete(existing)
        db.commit()
        audit.log(
            db=db,
            user=current_admin,
            action="UNASSIGN_DEVICE",
            target_type="device",
            target_id=device_id,
            ip=get_client_ip(request),
            detail={"user_id": user_id, "device_id": device_id},
        )

    return _to_user_response(db, target_user)


class DeviceAssign(BaseModel):
    device_ids: list[int] = Field(default_factory=list, max_length=200)


@router.get("/api/users/{user_id}/devices", response_model=DeviceAssign)
def get_user_devices(
    user_id: int,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:assign"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> DeviceAssign:
    """Retrieve device IDs assigned to a user (Admin only)."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    rows = (
        db.query(UserDevice.device_id)
        .filter(UserDevice.user_id == user_id)
        .order_by(UserDevice.device_id)
        .all()
    )
    return DeviceAssign(device_ids=[r[0] for r in rows])


@router.put("/api/users/{user_id}/devices", response_model=DeviceAssign)
def set_user_devices_batch(
    user_id: int,
    body: DeviceAssign,
    request: Request,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:assign"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> DeviceAssign:
    """Batch-assign devices to a user (Admin only)."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    wanted = set(body.device_ids)
    if wanted:
        from app.models.device import Device

        found_rows = db.query(Device.id).filter(Device.id.in_(wanted)).all()
        found_ids = {r[0] for r in found_rows}
        missing = wanted - found_ids
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Device not found: {sorted(missing)}",
            )

    db.query(UserDevice).filter(UserDevice.user_id == user_id).delete()
    for dev_id in sorted(wanted):
        db.add(UserDevice(user_id=user_id, device_id=dev_id))
    db.commit()

    audit.log(
        db=db,
        user=current_admin,
        action="ASSIGN_DEVICE",
        target_type="user",
        target_id=user_id,
        ip=get_client_ip(request),
        detail={"user_id": user_id, "devices": sorted(wanted)},
    )
    return DeviceAssign(device_ids=sorted(wanted))


@router.delete("/api/users/{user_id}/devices/{device_id}", response_model=UserResponse)
def unassign_device_from_user(
    user_id: int,
    device_id: int,
    request: Request,
    current_admin: User = Depends(
        require_role(*PERMISSION_MATRIX["devices:assign"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Remove a device assignment from a user in `user_devices` (Admin only)."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    existing = (
        db.query(UserDevice)
        .filter(
            UserDevice.user_id == user_id,
            UserDevice.device_id == device_id,
        )
        .first()
    )
    if existing is not None:
        db.delete(existing)
        db.commit()
        audit.log(
            db=db,
            user=current_admin,
            action="UNASSIGN_DEVICE",
            target_type="device",
            target_id=device_id,
            ip=get_client_ip(request),
            detail={"user_id": user_id, "device_id": device_id},
        )

    return _to_user_response(db, target_user)


