"""Password hashing, JWT creation/verification, and get_current_user dependency."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)

# Precomputed dummy bcrypt hash to mitigate timing-based user enumeration
_DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"dummy_Timing_Defense_Secret_99!", bcrypt.gensalt()).decode(
    "utf-8"
)

# In-memory store of revoked token JTIs (for logout within token lifetime)
_REVOKED_JTIS: set[str] = set()


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt directly.

    Args:
        plain_password: Raw password provided by the user.

    Returns:
        str: Bcrypt hash string suitable for storing in `users.password_hash`.
    """
    return bcrypt.hashpw(
        plain_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Args:
        plain_password: Raw password to check.
        password_hash: Stored bcrypt hash from database.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except ValueError:
        return False


def verify_dummy_password(plain_password: str) -> None:
    """Run dummy bcrypt check when email is not found to equalize response time."""
    bcrypt.checkpw(
        plain_password.encode("utf-8"),
        _DUMMY_BCRYPT_HASH.encode("utf-8"),
    )


def validate_password_strength(password: str) -> None:
    """Validate that a new password meets minimum complexity rules.

    Args:
        password: Candidate new password string.

    Raises:
        HTTPException: 422 if password is shorter than 8 chars or lacks upper/lower/digit.
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=422,
            detail="Password must be at least 8 characters long",
        )
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        raise HTTPException(
            status_code=422,
            detail="Password must contain uppercase, lowercase, and numeric characters",
        )


def create_access_token(
    user_id: int,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a short-lived signed JWT containing `sub`, `role`, `exp`, `iat`, `jti`.

    Args:
        user_id: Database ID of the authenticated user.
        role: User role (`admin`, `operator`, `viewer`).
        expires_delta: Custom expiration duration; defaults to `JWT_EXPIRE_MINUTES`.

    Returns:
        str: Encoded JWT string signed with `JWT_SECRET`.
    """
    now = datetime.now(timezone.utc)
    delta = (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.jwt_expire_minutes)
    )
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + delta,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Args:
        token: Raw Bearer JWT string.

    Returns:
        dict[str, Any]: Verified JWT payload dictionary.

    Raises:
        HTTPException: 401 if token is malformed, expired, revoked, or missing claims.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "role", "exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    jti = payload.get("jti")
    if jti and jti in _REVOKED_JTIS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def revoke_token(token: str) -> None:
    """Revoke a JWT access token by recording its `jti` identifier."""
    payload = decode_access_token(token)
    jti = payload.get("jti")
    if jti:
        _REVOKED_JTIS.add(str(jti))


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency returning the authenticated active User from Bearer JWT.

    Args:
        credentials: HTTP Authorization Bearer credentials extracted by FastAPI.
        db: Active SQLAlchemy database session.

    Returns:
        User: Authenticated SQLAlchemy User instance whose status is 'active'.

    Raises:
        HTTPException: 401 if Authorization header is missing, token signature/expiry
            is invalid, user no longer exists, or user account status is not 'active'.
    """
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is locked or disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
