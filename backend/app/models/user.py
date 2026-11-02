"""User and UserDevice ORM models owned by TV3 (integrated with TV2)."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _utcnow() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


class User(Base):
    """System user account with role, status, token_version, and login lockout tracking."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="viewer", index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    failed_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    @property
    def locked(self) -> bool:
        """Return True if account is currently within temporary lockout window."""
        if self.locked_until is None:
            return False
        now = datetime.now(timezone.utc)
        lu = (
            self.locked_until.replace(tzinfo=timezone.utc)
            if self.locked_until.tzinfo is None
            else self.locked_until
        )
        return lu > now


class UserDevice(Base):
    """Mapping table assigning accessible devices to users (Operator/Viewer)."""

    __tablename__ = "user_devices"

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
