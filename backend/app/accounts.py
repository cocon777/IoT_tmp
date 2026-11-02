from __future__ import annotations

import math
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.config import settings
from app.db import utcnow
from app.errors import AccountDisabled, AccountLocked, InvalidCredentials, InvalidInput, SelfLockout
from app.lifecycle import Conflict, NotFound
from app.models import Device, User, UserDevice
from app import security

ROLES = ("admin", "operator", "viewer", "Admin", "Operator", "Viewer")
STATUSES = ("active", "disabled", "locked")


def _resolve_actor_id(s: Session, actor_id: int | None) -> int | None:
    if actor_id is None:
        return None
    try:
        user = s.get(User, actor_id)
        return user.id if user else None
    except Exception:
        return None


def validate_new_password(password: str) -> None:
    if len(password) < getattr(settings, "min_password_len", 8):
        raise InvalidInput(f"Mật khẩu tối thiểu {getattr(settings, 'min_password_len', 8)} ký tự")
    if len(password.encode("utf-8")) > 72:
        raise InvalidInput("Mật khẩu tối đa 72 byte")


def get_user(s: Session, user_id: int) -> User:
    user = s.get(User, user_id)
    if user is None:
        raise NotFound("Không tìm thấy người dùng")
    return user


def authenticate(s: Session, email: str, password: str, ip: str) -> User:
    email = email.strip().lower()
    now = utcnow()
    user = s.scalars(select(User).where(User.email == email)).first()

    if user is None:
        security.dummy_verify(password)
        write_audit(s, None, "auth.login_failed", "user", "-", ip, f"email={email[:100]}")
        s.commit()
        raise InvalidCredentials()

    if user.locked_until and user.locked_until > now:
        write_audit(s, _resolve_actor_id(s, user.id), "auth.login_blocked", "user", user.id, ip)
        s.commit()
        raise AccountLocked(max(1, math.ceil((user.locked_until - now).total_seconds() / 60)))

    if not security.verify_password(password, user.password_hash):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        max_attempts = getattr(settings, "login_max_attempts", 5)
        lockout_min = getattr(settings, "lockout_minutes", 15)
        if user.failed_attempts >= max_attempts:
            user.failed_attempts = 0
            user.locked_until = now + timedelta(minutes=lockout_min)
            write_audit(
                s,
                _resolve_actor_id(s, user.id),
                "auth.locked",
                "user",
                user.id,
                ip,
                f"khóa {lockout_min} phút sau {max_attempts} lần sai",
            )
            s.commit()
            raise AccountLocked(lockout_min)
        write_audit(s, _resolve_actor_id(s, user.id), "auth.login_failed", "user", user.id, ip)
        s.commit()
        raise InvalidCredentials()

    if user.status != "active":
        write_audit(s, _resolve_actor_id(s, user.id), "auth.login_disabled", "user", user.id, ip)
        s.commit()
        raise AccountDisabled()

    user.failed_attempts = 0
    user.locked_until = None
    write_audit(s, _resolve_actor_id(s, user.id), "auth.login", "user", user.id, ip)
    s.commit()
    return user


def logout(s: Session, user_id: int, ip: str) -> None:
    user = get_user(s, user_id)
    user.token_version = (user.token_version or 0) + 1
    write_audit(s, _resolve_actor_id(s, user.id), "auth.logout", "user", user.id, ip)
    s.commit()


def change_password(s: Session, user_id: int, current: str, new: str, ip: str) -> User:
    user = get_user(s, user_id)
    if not security.verify_password(current, user.password_hash):
        raise InvalidInput("Mật khẩu hiện tại không đúng")
    validate_new_password(new)
    if new == current:
        raise InvalidInput("Mật khẩu mới phải khác mật khẩu cũ")
    user.password_hash = security.hash_password(new)
    user.token_version = (user.token_version or 0) + 1
    write_audit(s, _resolve_actor_id(s, user.id), "auth.change_password", "user", user.id, ip)
    s.commit()
    return user


def update_profile(s: Session, user_id: int, full_name: str, ip: str) -> User:
    user = get_user(s, user_id)
    user.full_name = full_name
    write_audit(s, _resolve_actor_id(s, user.id), "user.update_profile", "user", user.id, ip)
    s.commit()
    return user


def create_user(
    s: Session,
    *,
    email: str,
    password: str,
    full_name: str,
    role: str,
    actor_id: int | None,
    ip: str,
) -> User:
    email = email.strip().lower()
    if role not in ROLES:
        raise InvalidInput("Vai trò không hợp lệ")
    validate_new_password(password)
    if s.scalars(select(User).where(User.email == email)).first():
        raise Conflict(f"Email '{email}' đã tồn tại")
    user = User(
        email=email,
        password_hash=security.hash_password(password),
        full_name=full_name,
        role=role.lower(),
        status="active",
        token_version=0,
    )
    s.add(user)
    try:
        s.flush()
        write_audit(
            s,
            _resolve_actor_id(s, actor_id),
            "user.create",
            "user",
            user.id,
            ip,
            f"email={email} role={role}",
        )
        s.commit()
    except IntegrityError:
        s.rollback()
        raise Conflict(f"Email '{email}' đã tồn tại")
    return user


def update_user(
    s: Session,
    user_id: int,
    *,
    full_name: str | None,
    role: str | None,
    status: str | None,
    unlock: bool,
    actor_id: int | None,
    ip: str,
) -> User:
    user = get_user(s, user_id)
    if role is not None and role not in ROLES:
        raise InvalidInput("Vai trò không hợp lệ")
    if status is not None and status not in STATUSES:
        raise InvalidInput("Trạng thái không hợp lệ")
    if user.id == actor_id and (
        (role and role.lower() != user.role.lower())
        or (status and status != user.status)
    ):
        raise SelfLockout()

    changes = []
    if full_name is not None and full_name != user.full_name:
        user.full_name = full_name
        changes.append("full_name")
    if role is not None and role.lower() != user.role.lower():
        changes.append(f"role {user.role}->{role.lower()}")
        user.role = role.lower()
        user.token_version = (user.token_version or 0) + 1
    if status is not None and status != user.status:
        changes.append(f"status {user.status}->{status}")
        user.status = status
        user.token_version = (user.token_version or 0) + 1
    if unlock:
        user.failed_attempts = 0
        user.locked_until = None
        changes.append("unlock")
    write_audit(
        s,
        _resolve_actor_id(s, actor_id),
        "user.update",
        "user",
        user.id,
        ip,
        "; ".join(changes) or "no change",
    )
    s.commit()
    return user


def get_user_device_ids(s: Session, user_id: int) -> list[int]:
    get_user(s, user_id)
    return sorted(s.scalars(select(UserDevice.device_id).where(UserDevice.user_id == user_id)))


def set_user_devices(
    s: Session,
    user_id: int,
    device_ids: list[int],
    *,
    actor_id: int | None,
    ip: str,
) -> list[int]:
    get_user(s, user_id)
    wanted = set(device_ids)
    found = set(s.scalars(select(Device.id).where(Device.id.in_(wanted)))) if wanted else set()
    if wanted - found:
        raise InvalidInput(f"Thiết bị không tồn tại: {sorted(wanted - found)}")
    s.execute(delete(UserDevice).where(UserDevice.user_id == user_id))
    s.add_all(UserDevice(user_id=user_id, device_id=d) for d in sorted(wanted))
    write_audit(
        s,
        _resolve_actor_id(s, actor_id),
        "user.assign_devices",
        "user",
        user_id,
        ip,
        f"devices={sorted(wanted)}",
    )
    s.commit()
    return sorted(wanted)
