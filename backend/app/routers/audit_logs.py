"""Audit Log query router (`GET /api/audit-logs`, Admin only, S9)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.security.rbac import PERMISSION_MATRIX, require_role

router = APIRouter(tags=["audit-logs"])


class AuditLogItem(BaseModel):
    """Single audit log record returned by `GET /api/audit-logs`."""

    id: int
    user_id: int | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    detail: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogPage(BaseModel):
    """Paginated response of audit log records."""

    items: list[AuditLogItem]
    total: int
    page: int
    page_size: int


def _normalize_ts(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@router.get("/api/audit-logs", response_model=AuditLogPage)
def list_audit_logs(
    user_id: int | None = Query(default=None, description="Filter by user ID"),
    action: str | None = Query(default=None, description="Filter by action code"),
    from_ts: datetime | None = Query(
        default=None, alias="from", description="Start timestamp (ISO 8601)"
    ),
    to_ts: datetime | None = Query(
        default=None, alias="to", description="End timestamp (ISO 8601)"
    ),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(
        default=20, ge=1, le=200, description="Items per page"
    ),
    _admin: User = Depends(
        require_role(*PERMISSION_MATRIX["audit_logs:view"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> AuditLogPage:
    """Query audit logs with optional filters (`user_id`, `action`, `from`, `to`) and pagination (Admin only)."""
    query = db.query(AuditLog)

    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if action is not None:
        query = query.filter(AuditLog.action == action)
    if from_ts is not None:
        query = query.filter(AuditLog.created_at >= _normalize_ts(from_ts))
    if to_ts is not None:
        query = query.filter(AuditLog.created_at <= _normalize_ts(to_ts))

    total = query.count()
    offset = (page - 1) * page_size
    rows = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )

    return AuditLogPage(
        items=[AuditLogItem.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
