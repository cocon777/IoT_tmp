from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db, SessionLocal
from app.models.user import User
from app.security.auth import get_current_user


@dataclass
class Actor:
    id: int
    role: str
    ip: str


def current_actor(
    request: Request,
    user: User = Depends(get_current_user),
) -> Actor:
    client_ip = request.client.host if request.client else ""
    return Actor(id=user.id, role=user.role, ip=client_ip)


def require_roles(*roles: str):
    allowed = {r.strip().lower() for r in roles}

    def dependency(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> Actor:
        if user.role.lower() not in allowed:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: insufficient role permissions",
            )
        client_ip = request.client.host if request.client else ""
        return Actor(id=user.id, role=user.role, ip=client_ip)

    return dependency


any_user = require_roles("admin", "operator", "viewer", "Admin", "Operator", "Viewer")
