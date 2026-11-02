"""Account lockout after repeated failed logins and per-IP rate limiting (S6)."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import time

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.models.user import User

MAX_FAILED_ATTEMPTS: int = 5
LOCKOUT_DURATION_MINUTES: int = 15

# Per-IP sliding window rate limit for /api/auth/login
RATE_LIMIT_MAX_REQUESTS: int = 20
RATE_LIMIT_WINDOW_SECONDS: float = 60.0

_ip_request_timestamps: dict[str, deque[float]] = defaultdict(deque)


def utcnow() -> datetime:
    """Return current UTC datetime (monkeypatchable in tests to advance clock)."""
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    """Attach UTC timezone if SQLite returned a naive datetime."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_user_temporarily_locked(user: User, now: datetime | None = None) -> bool:
    """Check whether a user account is currently within its temporary lockout window.

    Args:
        user: User ORM instance to check.
        now: Optional reference UTC timestamp (defaults to `utcnow()`).

    Returns:
        bool: True if `user.locked_until` is set and in the future, False otherwise.
    """
    if user.locked_until is None:
        return False
    current_time = _ensure_utc(now or utcnow())
    locked_until_utc = _ensure_utc(user.locked_until)
    return locked_until_utc > current_time


def record_failed_login(
    db: Session,
    user: User,
    now: datetime | None = None,
) -> bool:
    """Increment `failed_attempts` and set `locked_until` when reaching 5 failures.

    Args:
        db: Active SQLAlchemy session.
        user: User ORM instance who failed authentication.
        now: Optional reference UTC timestamp (defaults to `utcnow()`).

    Returns:
        bool: True if this failure triggered a temporary account lockout, False otherwise.
    """
    current_time = _ensure_utc(now or utcnow())

    # If a previous lockout window has already expired, start counting fresh
    if user.locked_until is not None and _ensure_utc(user.locked_until) <= current_time:
        user.failed_attempts = 0
        user.locked_until = None

    user.failed_attempts = (user.failed_attempts or 0) + 1
    triggered_lockout = False

    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = current_time + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        triggered_lockout = True

    db.add(user)
    db.commit()
    db.refresh(user)
    return triggered_lockout


def reset_login_attempts(db: Session, user: User) -> None:
    """Reset `failed_attempts` and `locked_until` upon a successful login.

    Args:
        db: Active SQLAlchemy session.
        user: User ORM instance who authenticated successfully.
    """
    if user.failed_attempts != 0 or user.locked_until is not None:
        user.failed_attempts = 0
        user.locked_until = None
        db.add(user)
        db.commit()
        db.refresh(user)


def get_client_ip(request: Request) -> str:
    """Extract client IP address from X-Forwarded-For header or socket peer."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def check_login_rate_limit(request: Request) -> None:
    """Enforce sliding-window per-IP rate limiting on `/api/auth/login`.

    Raises:
        HTTPException: 429 Too Many Requests if the client IP exceeds
            `RATE_LIMIT_MAX_REQUESTS` within `RATE_LIMIT_WINDOW_SECONDS`.
    """
    client_ip = get_client_ip(request)
    now_mono = time.monotonic()
    cutoff = now_mono - RATE_LIMIT_WINDOW_SECONDS

    bucket = _ip_request_timestamps[client_ip]
    while bucket and bucket[0] <= cutoff:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login requests from this IP. Please try again later.",
            headers={"Retry-After": str(int(RATE_LIMIT_WINDOW_SECONDS))},
        )

    bucket.append(now_mono)


def reset_rate_limiter() -> None:
    """Clear in-memory IP rate limit buckets (used by automated tests)."""
    _ip_request_timestamps.clear()
