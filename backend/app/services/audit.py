"""Audit logging service (`audit.log`) shared between TV3 and TV2 (S9)."""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|jwt|authorization|credential)",
    re.IGNORECASE,
)


def _sanitize_detail(detail: str | dict[str, Any] | None) -> str | None:
    """Sanitize `detail` so passwords, tokens, or secrets are never stored."""
    if detail is None:
        return None
    if isinstance(detail, dict):
        cleaned: dict[str, Any] = {}
        for k, v in detail.items():
            if _SENSITIVE_KEY_PATTERN.search(str(k)):
                cleaned[str(k)] = "[REDACTED]"
            else:
                cleaned[str(k)] = v
        return json.dumps(cleaned, ensure_ascii=False)

    text = str(detail)
    # Redact any accidental key=value or JSON fields with sensitive names
    text = re.sub(
        r'("?(?:password|old_password|new_password|token|access_token|secret)"?\s*[:=]\s*)("[^"]*"|\S+)',
        r'\1"[REDACTED]"',
        text,
        flags=re.IGNORECASE,
    )
    return text


def log(
    db: Session,
    user: User | int | None,
    action: str,
    target_type: str | None = None,
    target_id: str | int | None = None,
    ip: str | None = None,
    detail: str | dict[str, Any] | None = None,
) -> AuditLog:
    """Record a security or operational event in the `audit_logs` table.

    Shared interface function handed off to TV2 (for pump commands, config
    updates, device provisioning/revocation) and used across TV3 modules.
    Automatically scrubs sensitive keys (`password`, `token`, `secret`) from `detail`.

    Args:
        db: Active SQLAlchemy database session.
        user: Authenticated `User` ORM instance, user ID (`int`), or `None`
            (e.g. failed login for unknown account).
        action: Short uppercase action code (e.g. `'LOGIN_SUCCESS'`, `'SEND_COMMAND'`).
        target_type: Resource type affected (e.g. `'user'`, `'device'`, `'endpoint'`).
        target_id: Identifier of the target resource (converted to `str` if provided).
        ip: Client IPv4/IPv6 address string.
        detail: Optional human-readable string or JSON-serializable dict with non-sensitive context.

    Returns:
        AuditLog: Persisted `AuditLog` ORM record.

    Raises:
        SQLAlchemyError: If the database write fails.
    """
    if isinstance(user, User):
        resolved_user_id: int | None = user.id
    elif isinstance(user, int):
        resolved_user_id = user
    else:
        resolved_user_id = None

    entry = AuditLog(
        user_id=resolved_user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=ip,
        detail=_sanitize_detail(detail),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
