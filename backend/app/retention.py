"""Telemetry retention cleanup for SQLite mode (TV2)."""

from datetime import timedelta
import logging
import threading

from sqlalchemy import delete, select

from app.config import settings
from app.db import session_scope, utcnow
from app.models.device import Telemetry

log = logging.getLogger("retention")


def purge_old_telemetry(days: int | None = None, batch: int = 20000) -> int:
    """Delete telemetry rows older than `days` in batches."""
    cutoff = utcnow() - timedelta(
        days=settings.telemetry_retention_days if days is None else days
    )
    total = 0
    while True:
        with session_scope() as s:
            ids = select(Telemetry.id).where(Telemetry.ts < cutoff).limit(batch)
            deleted = s.execute(delete(Telemetry).where(Telemetry.id.in_(ids))).rowcount
        total += deleted
        if deleted < batch:
            return total


def run_retention_watcher(stop: threading.Event, interval_s: float = 3600.0) -> None:
    """Background worker periodically purging expired telemetry rows."""
    while True:
        try:
            removed = purge_old_telemetry()
            if removed:
                log.info(
                    "đã xóa %d bản ghi telemetry quá %d ngày",
                    removed,
                    settings.telemetry_retention_days,
                )
        except Exception:
            log.exception("retention lỗi")
        if stop.wait(interval_s):
            return
