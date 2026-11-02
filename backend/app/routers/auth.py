"""Authentication router (/api/auth/login, /api/auth/logout, /api/auth/change-password, /api/me)."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.user import User
from app.security.auth import (
    bearer_scheme,
    create_access_token,
    get_current_user,
    hash_password,
    revoke_token,
    validate_password_strength,
    verify_dummy_password,
    verify_password,
)
from app.security.lockout import (
    check_login_rate_limit,
    get_client_ip,
    is_user_temporarily_locked,
    record_failed_login,
    reset_login_attempts,
)
from app.services import audit

router = APIRouter(tags=["auth"])

GENERIC_AUTH_ERROR = "Invalid email or password"
TEMP_LOCKED_ERROR = (
    "Account is temporarily locked due to multiple failed login attempts"
)


class LoginRequest(BaseModel):
    """Request payload for user login."""

    email: EmailStr
    password: str


class UserPublic(BaseModel):
    """Public representation of a user account (never exposes password_hash)."""

    id: int
    email: EmailStr
    full_name: str
    role: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """Response returned upon successful authentication."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserPublic


class ChangePasswordRequest(BaseModel):
    """Request payload for changing the current user's password."""

    old_password: str
    new_password: str


class ProfileUpdateRequest(BaseModel):
    """Request payload for updating own user profile."""

    full_name: str


@router.post(
    "/api/auth/login",
    response_model=TokenResponse,
    dependencies=[Depends(check_login_rate_limit)],
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate user by email and password and issue a short-lived JWT.

    Enforces per-IP rate limiting, checks permanent status and temporary lockout
    (`locked_until`), increments `failed_attempts` on bad password (locking for
    15 minutes upon reaching 5 consecutive failures), and resets the counter
    upon successful login.
    """
    client_ip = get_client_ip(request)
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None:
        verify_dummy_password(payload.password)
        audit.log(
            db=db,
            user=None,
            action="LOGIN_FAILED",
            target_type="user",
            target_id=payload.email,
            ip=client_ip,
            detail="Login failed: unknown email",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_AUTH_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != "active":
        audit.log(
            db=db,
            user=user,
            action="LOGIN_FAILED",
            target_type="user",
            target_id=user.id,
            ip=client_ip,
            detail=f"Login rejected: account status is {user.status}",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked or disabled",
        )

    if is_user_temporarily_locked(user):
        audit.log(
            db=db,
            user=user,
            action="LOGIN_FAILED",
            target_type="user",
            target_id=user.id,
            ip=client_ip,
            detail="Login rejected: account is temporarily locked",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=TEMP_LOCKED_ERROR,
        )

    if not verify_password(payload.password, user.password_hash):
        just_locked = record_failed_login(db, user)
        audit.log(
            db=db,
            user=user,
            action="LOGIN_FAILED",
            target_type="user",
            target_id=user.id,
            ip=client_ip,
            detail=f"Invalid password (failed_attempts={user.failed_attempts})",
        )
        if just_locked:
            audit.log(
                db=db,
                user=user,
                action="ACCOUNT_LOCKED",
                target_type="user",
                target_id=user.id,
                ip=client_ip,
                detail=f"Account temporarily locked after {user.failed_attempts} failed attempts",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_AUTH_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    reset_login_attempts(db, user)
    audit.log(
        db=db,
        user=user,
        action="LOGIN_SUCCESS",
        target_type="user",
        target_id=user.id,
        ip=client_ip,
        detail="User logged in successfully",
    )
    token = create_access_token(user_id=user.id, role=user.role)
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_expire_minutes * 60,
        user=UserPublic.model_validate(user),
    )


@router.get("/api/me", response_model=UserPublic)
def read_current_user(
    current_user: User = Depends(get_current_user),
) -> UserPublic:
    """Return profile information for the currently authenticated user."""
    return UserPublic.model_validate(current_user)


@router.patch("/api/me", response_model=UserPublic)
def update_current_user_profile(
    payload: ProfileUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserPublic:
    """Update profile full_name for the currently authenticated user."""
    current_user.full_name = payload.full_name
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    audit.log(
        db=db,
        user=current_user,
        action="UPDATE_PROFILE",
        target_type="user",
        target_id=current_user.id,
        ip=get_client_ip(request),
        detail=f"User updated profile name to {payload.full_name}",
    )
    return UserPublic.model_validate(current_user)


@router.post("/api/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Change password for the currently authenticated user after verifying old password."""
    if not verify_password(payload.old_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    if payload.old_password == payload.new_password:
        raise HTTPException(
            status_code=422,
            detail="New password must be different from the current password",
        )

    validate_password_strength(payload.new_password)
    current_user.password_hash = hash_password(payload.new_password)
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    db.add(current_user)
    db.commit()
    audit.log(
        db=db,
        user=current_user,
        action="CHANGE_PASSWORD",
        target_type="user",
        target_id=current_user.id,
        ip=get_client_ip(request),
        detail="User changed own password",
    )
    return {"message": "Password changed successfully"}


@router.post("/api/auth/logout")
def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Invalidate the current JWT access token and log out the user."""
    if credentials and credentials.credentials:
        revoke_token(credentials.credentials)
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    db.add(current_user)
    db.commit()
    audit.log(
        db=db,
        user=current_user,
        action="LOGOUT",
        target_type="user",
        target_id=current_user.id,
        ip=get_client_ip(request),
        detail="User logged out successfully",
    )
    return {"message": "Logged out successfully"}
