"""Role-Based Access Control (RBAC) and device-scope authorization (S7).

Provides the shared authorization interfaces handed off to TV2 and TV4:
- `require_role(*roles)`
- `can_access_device(user, device_id, db=None)`
- `require_device_access(device_id, current_user, db)`
- `PERMISSION_MATRIX`: canonical 13-row permission matrix from section 1.2.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session, object_session

from app.db import SessionLocal, get_db
from app.models.device_stub import DeviceStub
from app.models.user import User, UserDevice
from app.security.auth import get_current_user
from app.security.lockout import get_client_ip
from app.services import audit


@dataclass(frozen=True)
class PermissionSpec:
    """Specification of a single row in the section 1.2 RBAC permission matrix."""

    action: str
    description_vi: str
    allowed_roles: tuple[str, ...]
    scoped_to_assigned_device: bool


# Ma tran quyen (Muc 1.2 AGENT_PLAN_TV3.md):
# - allowed_roles: cac vai tro duoc phep thuc hien hanh dong
# - scoped_to_assigned_device: True neu Operator/Viewer chi duoc thao tac tren thiet bi duoc gan (◐)
PERMISSION_MATRIX: dict[str, PermissionSpec] = {
    "users:manage": PermissionSpec(
        action="users:manage",
        description_vi="Quản lý người dùng (tạo, khóa, đổi vai trò)",
        allowed_roles=("admin",),
        scoped_to_assigned_device=False,
    ),
    "account:self": PermissionSpec(
        action="account:self",
        description_vi="Xem/sửa tài khoản của mình, đổi mật khẩu",
        allowed_roles=("admin", "operator", "viewer"),
        scoped_to_assigned_device=False,
    ),
    "devices:lifecycle_admin": PermissionSpec(
        action="devices:lifecycle_admin",
        description_vi="Đăng ký, cấp credential, thu hồi thiết bị",
        allowed_roles=("admin",),
        scoped_to_assigned_device=False,
    ),
    "devices:assign": PermissionSpec(
        action="devices:assign",
        description_vi="Gán thiết bị cho người dùng và khu vực",
        allowed_roles=("admin",),
        scoped_to_assigned_device=False,
    ),
    "devices:view": PermissionSpec(
        action="devices:view",
        description_vi="Xem danh sách và trạng thái thiết bị",
        allowed_roles=("admin", "operator", "viewer"),
        scoped_to_assigned_device=True,
    ),
    "telemetry:view": PermissionSpec(
        action="telemetry:view",
        description_vi="Xem dữ liệu hiện tại, lịch sử, biểu đồ",
        allowed_roles=("admin", "operator", "viewer"),
        scoped_to_assigned_device=True,
    ),
    "telemetry:export_csv": PermissionSpec(
        action="telemetry:export_csv",
        description_vi="Xuất dữ liệu CSV",
        allowed_roles=("admin", "operator"),
        scoped_to_assigned_device=True,
    ),
    "devices:update_config": PermissionSpec(
        action="devices:update_config",
        description_vi="Đổi cấu hình và ngưỡng cảnh báo",
        allowed_roles=("admin", "operator"),
        scoped_to_assigned_device=True,
    ),
    "devices:send_command": PermissionSpec(
        action="devices:send_command",
        description_vi="Gửi lệnh bật/tắt bơm",
        allowed_roles=("admin", "operator"),
        scoped_to_assigned_device=True,
    ),
    "devices:set_maintenance": PermissionSpec(
        action="devices:set_maintenance",
        description_vi="Chuyển thiết bị sang Maintenance",
        allowed_roles=("admin", "operator"),
        scoped_to_assigned_device=True,
    ),
    "alerts:view": PermissionSpec(
        action="alerts:view",
        description_vi="Xem cảnh báo",
        allowed_roles=("admin", "operator", "viewer"),
        scoped_to_assigned_device=True,
    ),
    "alerts:ack_close": PermissionSpec(
        action="alerts:ack_close",
        description_vi="Xác nhận (ack) và đóng cảnh báo",
        allowed_roles=("admin", "operator"),
        scoped_to_assigned_device=True,
    ),
    "audit_logs:view": PermissionSpec(
        action="audit_logs:view",
        description_vi="Xem audit log",
        allowed_roles=("admin",),
        scoped_to_assigned_device=False,
    ),
}


def require_role(*roles: str) -> Callable[..., User]:
    """Create a FastAPI dependency that restricts access to the specified roles.

    Args:
        *roles: One or more role names allowed to access the endpoint
            (e.g. `'admin'`, `'operator'`, `'viewer'`).

    Returns:
        Callable[..., User]: FastAPI dependency returning the authenticated `User`
            if their role is in `roles`.

    Raises:
        HTTPException: 401 if unauthenticated; 403 if the user's role is not in `roles`.
    """
    allowed = {r.lower() for r in roles}

    def _role_dependency(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if (current_user.role or "").lower() not in allowed:
            audit.log(
                db=db,
                user=current_user,
                action="PERMISSION_DENIED",
                target_type="endpoint",
                target_id=f"{request.method} {request.url.path}",
                ip=get_client_ip(request),
                detail=f"Role '{current_user.role}' not in allowed roles {sorted(allowed)}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions",
            )
        return current_user

    return _role_dependency


def can_access_device(
    user: User,
    device_id: int,
    db: Session | None = None,
) -> bool:
    """Check whether `user` is permitted to access `device_id`.

    Admin users can access all devices. Operator and Viewer users can only access
    devices explicitly assigned to them in the `user_devices` table.

    Args:
        user: Authenticated `User` ORM instance.
        device_id: Primary key ID of the target device.
        db: Optional SQLAlchemy session. If omitted, uses `object_session(user)`
            or opens a temporary session from `SessionLocal`.

    Returns:
        bool: True if the user is allowed to access the device, False otherwise.
    """
    if user is None or user.status != "active":
        return False

    if (user.role or "").lower() == "admin":
        return True

    session = db or object_session(user)
    close_after = False
    if session is None:
        session = SessionLocal()
        close_after = True

    try:
        assignment = (
            session.query(UserDevice)
            .filter(
                UserDevice.user_id == user.id,
                UserDevice.device_id == device_id,
            )
            .first()
        )
        return assignment is not None
    finally:
        if close_after:
            session.close()


def require_device_access(
    device_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency verifying the user can access `device_id` in path/query.

    Returns 404 (not 403) when a device is outside the user's assigned scope so
    that the API does not leak whether an unassigned device ID exists.

    Args:
        device_id: Target device ID extracted from path or query parameters.
        request: Active HTTP request (used to record client IP in audit logs).
        current_user: Authenticated `User` resolved by `get_current_user`.
        db: Active SQLAlchemy database session.

    Returns:
        User: Authenticated `User` if access to `device_id` is permitted.

    Raises:
        HTTPException: 401 if unauthenticated; 404 if the device does not exist
            or is outside the user's assigned scope in `user_devices`.
    """
    if not can_access_device(current_user, device_id, db=db):
        audit.log(
            db=db,
            user=current_user,
            action="PERMISSION_DENIED",
            target_type="device",
            target_id=str(device_id),
            ip=get_client_ip(request),
            detail=f"Out-of-scope device access attempt on {request.method} {request.url.path}",
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    device = db.query(DeviceStub).filter(DeviceStub.id == device_id).first()
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    return current_user
