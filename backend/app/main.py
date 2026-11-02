"""FastAPI entrypoint for WMS Backend (Integrated TV2 + TV3)."""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI

from app import alerts as alert_engine
from app import events
from app.broker_admin import get_broker_admin
from app.commands import run_command_watcher
from app.config import settings
from app.db import Base, engine
from app.errors import install_error_handlers
from app.ingest import run_offline_watcher
from app.mqtt_client import get_subscriber
from app.realtime import hub
from app.retention import run_retention_watcher

import app.models  # noqa: F401 - register ORM models with Base.metadata

from app.routers.alerts import router as alerts_router
from app.routers.audit_logs import router as audit_logs_router
from app.routers.auth import router as auth_router
from app.routers.commands import router as commands_router
from app.routers.config import router as config_router
from app.routers.devices import router as devices_router
from app.routers.telemetry import router as telemetry_router
from app.routers.users import router as users_router
from app.routers.ws import router as ws_router

log = logging.getLogger("main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize database schema, MQTT subscribers, event dispatcher, and background watchers."""
    if settings.is_sqlite or getattr(settings, "auto_create_tables", True):
        Base.metadata.create_all(bind=engine)

    stop = threading.Event()
    events.set_event_callback(hub.publish)

    subscriber = get_subscriber()
    alert_engine.set_publisher(subscriber)
    broker_admin = get_broker_admin()

    try:
        broker_admin.start()
    except Exception as exc:
        log.warning("Could not start broker admin: %s", exc)

    if settings.broker_admin != "none" or settings.mqtt_host not in ("", "none", "localhost"):
        try:
            subscriber.start()
        except Exception as exc:
            log.warning("Could not start MQTT subscriber: %s", exc)

    # Launch background watchers
    t_offline = threading.Thread(target=run_offline_watcher, args=(stop,), daemon=True)
    t_cmd = threading.Thread(target=run_command_watcher, args=(stop,), daemon=True)
    t_offline.start()
    t_cmd.start()

    if settings.is_sqlite:
        t_retention = threading.Thread(target=run_retention_watcher, args=(stop,), daemon=True)
        t_retention.start()

    yield

    stop.set()
    events.set_event_callback(lambda event, payload: None)
    alert_engine.shutdown()
    try:
        broker_admin.stop()
    except Exception:
        pass
    try:
        subscriber.stop()
    except Exception:
        pass


app = FastAPI(
    title="Smart Water Management System API",
    version="0.2.0",
    lifespan=lifespan,
)

install_error_handlers(app)

# Include all core API routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(audit_logs_router)
app.include_router(devices_router)
app.include_router(telemetry_router)
app.include_router(commands_router)
app.include_router(config_router)
app.include_router(alerts_router)
app.include_router(ws_router)


@app.get("/health")
@app.get("/api/health")
def health_check() -> dict[str, str]:
    """Return service health status."""
    return {"status": "ok"}
