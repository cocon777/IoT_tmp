"""Bridge module connecting TV2's transactional `write_audit` to TV3's `services.audit` sanitizer."""

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services.audit import _sanitize_detail, log

__all__ = ["log", "write_audit"]


def write_audit(
    s: Session,
    user_id: int | None,
    action: str,
    target_type: str,
    target_id: int | str,
    ip: str,
    detail: str = "",
) -> None:
    """Add a sanitized AuditLog entry to the active session `s` (committed with caller transaction)."""
    sanitized = _sanitize_detail(detail) or ""
    s.add(
        AuditLog(
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=str(target_id),
            ip=(ip or "")[:64],
            detail=sanitized[:512],
        )
    )
