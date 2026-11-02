"""Internal real-time event hook connecting ingestion/alerts/commands to WebSocket hub (TV2)."""

import logging
from typing import Any, Callable

log = logging.getLogger("events")
_callback: Callable[[str, dict[str, Any]], None] = lambda event, payload: None


def set_event_callback(cb: Callable[[str, dict[str, Any]], None]) -> None:
    """Register callback invoked whenever a domain event is emitted."""
    global _callback
    _callback = cb


def emit(event: str, payload: dict[str, Any]) -> None:
    """Emit a domain event to the registered real-time callback."""
    try:
        _callback(event, payload)
    except Exception:
        log.exception("event callback failed (%s)", event)
