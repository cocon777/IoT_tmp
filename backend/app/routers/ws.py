"""WebSocket endpoint `/ws` with first-message JWT authentication, device-scope filtering, and real-time push."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.db import get_db, SessionLocal
from app.models.user import User
from app.realtime import hub, EVENT_ROLES
from app.security.auth import decode_access_token, get_current_user
from app.security.rbac import can_access_device, require_role, PERMISSION_MATRIX

log = logging.getLogger("ws")
router = APIRouter(tags=["websocket", "realtime"])

WS_AUTH_TIMEOUT_SECONDS: float = 5.0


def should_deliver_event(
    user: User,
    event: dict[str, Any],
    db: Session,
) -> bool:
    """Filter a real-time event according to the user's assigned device scope.

    Args:
        user: Authenticated `User` ORM instance.
        event: Event payload dictionary containing `device_id`.
        db: Active SQLAlchemy database session.

    Returns:
        bool: True if the user is allowed to receive `event`, False otherwise.
    """
    device_id = event.get("device_id")
    if device_id is None:
        return True
    try:
        resolved_device_id = int(device_id)
    except (TypeError, ValueError):
        return False
    return can_access_device(user, resolved_device_id, db=db)


def build_fake_periodic_events() -> list[dict[str, Any]]:
    """Return a batch of simulated telemetry/alert events across devices 1 and 2."""
    return [
        {
            "type": "telemetry",
            "device_id": 1,
            "device_code": "wms-001",
            "level_pct": 74.0,
            "flow_lpm": 3.1,
        },
        {
            "type": "telemetry",
            "device_id": 2,
            "device_code": "wms-002",
            "level_pct": 48.5,
            "flow_lpm": 1.8,
        },
    ]


def _authenticate_ws_token(token: str, db: Session) -> User:
    """Validate JWT string and return the active User or raise HTTPException."""
    payload = decode_access_token(token)
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        ) from exc

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account is locked",
        )
    return user


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    db: Session = Depends(get_db),
) -> None:
    """Authenticate WebSocket via first message `{"type":"auth","token":"..."}` within 5s.

    Closes connection immediately on missing/invalid/expired token or when the user's
    account status becomes locked/disabled. Filters all outgoing device events
    using `can_access_device`.
    """
    await websocket.accept()

    try:
        raw_first = await asyncio.wait_for(
            websocket.receive_text(),
            timeout=WS_AUTH_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        await websocket.send_json(
            {"type": "auth_error", "detail": "Authentication timeout (5s exceeded)"}
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    except WebSocketDisconnect:
        return

    try:
        auth_msg = json.loads(raw_first)
    except json.JSONDecodeError:
        await websocket.send_json(
            {"type": "auth_error", "detail": "First message must be valid JSON"}
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if (
        not isinstance(auth_msg, dict)
        or auth_msg.get("type") != "auth"
        or not isinstance(auth_msg.get("token"), str)
    ):
        await websocket.send_json(
            {
                "type": "auth_error",
                "detail": 'First message must be {"type":"auth","token":"..."}',
            }
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        user = _authenticate_ws_token(auth_msg["token"], db)
    except HTTPException as exc:
        await websocket.send_json({"type": "auth_error", "detail": exc.detail})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.send_json(
        {"type": "auth_ok", "user_id": user.id, "role": user.role}
    )

    # Setup queue for hub events
    event_queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    loop = asyncio.get_running_loop()

    def on_hub_event(event_type: str, payload: dict) -> None:
        try:
            with SessionLocal() as s:
                u = s.get(User, user.id)
                if u and u.status == "active" and should_deliver_event(u, payload, s):
                    msg = {"type": event_type, **payload}
                    loop.call_soon_threadsafe(
                        lambda: event_queue.put_nowait(msg) if not event_queue.full() else None
                    )
        except Exception:
            pass

    # We register listener with a callback hook if needed
    try:
        while True:
            # Check user status
            db.expire_all()
            fresh_user = db.query(User).filter(User.id == user.id).first()
            if fresh_user is None or fresh_user.status != "active":
                await websocket.send_json(
                    {"type": "error", "detail": "Account is locked or disabled"}
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            # Wait for either incoming message or event
            recv_task = asyncio.create_task(websocket.receive_text())
            queue_task = asyncio.create_task(event_queue.get())

            done, pending = await asyncio.wait(
                [recv_task, queue_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            if queue_task in done:
                event_data = queue_task.result()
                await websocket.send_json(event_data)

            if recv_task in done:
                raw_msg = recv_task.result()
                db.expire_all()
                fresh_user = db.query(User).filter(User.id == user.id).first()
                if fresh_user is None or fresh_user.status != "active":
                    await websocket.send_json(
                        {"type": "error", "detail": "Account is locked or disabled"}
                    )
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return

                try:
                    cmd = json.loads(raw_msg)
                except json.JSONDecodeError:
                    continue

                if isinstance(cmd, dict) and cmd.get("type") == "simulate_tick":
                    for event in build_fake_periodic_events():
                        if should_deliver_event(fresh_user, event, db):
                            await websocket.send_json(event)
                elif isinstance(cmd, dict) and cmd.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif isinstance(cmd, dict) and cmd.get("type") == "subscribe":
                    await websocket.send_json({"type": "subscribed", **cmd})
    except WebSocketDisconnect:
        return


@router.get("/api/metrics/latency")
def latency_stats(
    _admin: User = Depends(require_role("admin", "Admin")),
):
    """Độ trễ telemetry (ms) trên các mẫu gần nhất: device_to_backend, backend_to_push, end_to_push."""
    return hub.stats.summary()


@router.delete("/api/metrics/latency", status_code=204)
def reset_latency_stats(
    _admin: User = Depends(require_role("admin", "Admin")),
):
    """Xóa bộ đếm độ trễ"""
    hub.stats.reset()
