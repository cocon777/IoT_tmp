"""WebSocket realtime hub: dispatches internal events (events.emit) to connected clients based on role and device scope."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime
import json
import logging
import math
import threading
import time

import jwt
from sqlalchemy import select

from app.config import settings
from app.db import SessionLocal, utcnow
from app.models import User, UserDevice
from app.security import decode_token

log = logging.getLogger("realtime")

_ALL_ROLES = ("admin", "operator", "viewer", "Admin", "Operator", "Viewer")
_OPERATORS = ("admin", "operator", "Admin", "Operator")
EVENT_ROLES = {
    "telemetry": _ALL_ROLES,
    "alert": _ALL_ROLES,
    "device_state": _ALL_ROLES,
    "command_result": _OPERATORS,
    "config": _OPERATORS,
    "config_applied": _OPERATORS,
}
ALL_EVENTS = tuple(EVENT_ROLES)
MAX_CLIENT_MESSAGE = 4096
CLIENT_RATE = (20, 10.0)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", ""))


@dataclass(frozen=True)
class Identity:
    user_id: int
    role: str
    exp: float
    tv: int | None
    devices: frozenset | None


def _devices_for(s, user: User):
    if user.role.lower() == "admin":
        return None
    rows = s.scalars(select(UserDevice.device_id).where(UserDevice.user_id == user.id)).all()
    return frozenset(rows)


def load_identity(token: str) -> Identity | None:
    try:
        claims = decode_token(token)
        user_id = int(claims["sub"])
    except Exception:
        return None
    with SessionLocal() as s:
        user = s.get(User, user_id)
        if user is None or user.status != "active":
            return None
        token_tv = claims.get("tv")
        if token_tv is not None and getattr(user, "token_version", 0) != token_tv:
            return None
        return Identity(
            user.id,
            user.role,
            float(claims.get("exp", time.time() + 3600)),
            getattr(user, "token_version", 0),
            _devices_for(s, user),
        )


def refresh_identity(old: Identity) -> Identity | None:
    with SessionLocal() as s:
        user = s.get(User, old.user_id)
        if user is None or user.status != "active":
            return None
        if old.tv is not None and getattr(user, "token_version", 0) != old.tv:
            return None
        return replace(old, role=user.role, devices=_devices_for(s, user))


def _stat(values: list[float]) -> dict:
    if not values:
        return {"avg": None, "p95": None, "max": None}
    ordered = sorted(values)
    p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
    return {
        "avg": round(sum(values) / len(values), 1),
        "p95": round(p95, 1),
        "max": round(ordered[-1], 1),
    }


class LatencyStats:
    def __init__(self, size: int = 2000):
        self._lock = threading.Lock()
        self._rows: deque = deque(maxlen=size)
        self.size = size

    def record(self, payload: dict, sent_at: datetime) -> None:
        try:
            ts, received = _parse(payload["ts"]), _parse(payload["received_at"])
        except (KeyError, ValueError, TypeError, AttributeError):
            return
        row = (
            (received - ts).total_seconds() * 1000,
            (sent_at - received).total_seconds() * 1000,
            (sent_at - ts).total_seconds() * 1000,
        )
        with self._lock:
            self._rows.append(row)

    def summary(self) -> dict:
        with self._lock:
            rows = list(self._rows)
        return {
            "samples": len(rows),
            "window": self.size,
            "device_to_backend_ms": _stat([r[0] for r in rows]),
            "backend_to_push_ms": _stat([r[1] for r in rows]),
            "end_to_push_ms": _stat([r[2] for r in rows]),
        }

    def reset(self) -> None:
        with self._lock:
            self._rows.clear()


class Client:
    def __init__(self, ws, ident: Identity, loop):
        self.ws, self.ident, self.loop = ws, ident, loop
        queue_size = getattr(settings, "ws_queue_size", 256)
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self.devices_filter: frozenset | None = None
        self.events_filter: frozenset | None = None
        self.close_code, self.close_error = 1000, None
        self._times: deque = deque()

    def wants(self, event: str, device_id) -> bool:
        roles = EVENT_ROLES.get(event)
        if (
            roles is None
            or (self.ident.role not in roles and self.ident.role.lower() not in roles)
            or not isinstance(device_id, int)
            or isinstance(device_id, bool)
        ):
            return False
        scope = self.ident.devices
        if scope is not None and device_id not in scope:
            return False
        if self.devices_filter is not None and device_id not in self.devices_filter:
            return False
        return self.events_filter is None or event in self.events_filter

    def offer(self, msg: str) -> None:
        try:
            self.queue.put_nowait(msg)
        except asyncio.QueueFull:
            self.close_with(1013, "slow_consumer", "Máy khách nhận quá chậm, hãy kết nối lại")
            while not self.queue.empty():
                self.queue.get_nowait()
            self.queue.put_nowait(None)

    def send_event(self, event: str, data: dict) -> None:
        self.offer(
            json.dumps(
                {"event": event, "data": data, "sent_at": _iso(utcnow())},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )

    def send_error(self, code: str, message: str) -> None:
        self.send_event("error", {"code": code, "message": message})

    def close_with(self, code: int, error_code: str, message: str) -> None:
        self.close_code, self.close_error = code, (error_code, message)

    def handle_message(self, text: str) -> bool:
        now = time.monotonic()
        while self._times and now - self._times[0] > CLIENT_RATE[1]:
            self._times.popleft()
        self._times.append(now)
        if len(text) > MAX_CLIENT_MESSAGE:
            self.close_with(1009, "message_too_big", "Thông điệp quá lớn")
            return False
        if len(self._times) > CLIENT_RATE[0]:
            self.close_with(1008, "rate_limited", "Gửi quá nhiều thông điệp")
            return False
        try:
            msg = json.loads(text)
            kind = msg.get("type")
        except (ValueError, AttributeError):
            self.send_error("bad_message", "Thông điệp phải là JSON object có trường type")
            return True
        if kind == "ping":
            self.send_event("pong", {})
        elif kind == "subscribe":
            self._subscribe(msg)
        elif kind == "auth":
            self.send_error("already_authenticated", "Kết nối đã được xác thực")
        else:
            self.send_error("unknown_type", f"Không hỗ trợ type: {str(kind)[:30]}")
        return True

    def _subscribe(self, msg: dict) -> None:
        devs, evs = msg.get("device_ids"), msg.get("events")
        new_devs = new_evs = None
        if devs is not None:
            if not (
                isinstance(devs, list)
                and len(devs) <= 200
                and all(isinstance(x, int) and not isinstance(x, bool) for x in devs)
            ):
                return self.send_error("bad_message", "device_ids phải là danh sách số nguyên (tối đa 200)")
            if self.ident.devices is not None and not set(devs) <= self.ident.devices:
                return self.send_error("forbidden_device", "Có thiết bị ngoài phạm vi của bạn")
            new_devs = frozenset(devs)
        if evs is not None:
            allowed = {e for e, roles in EVENT_ROLES.items() if self.ident.role in roles or self.ident.role.lower() in roles}
            if not (isinstance(evs, list) and all(isinstance(x, str) for x in evs)) or not set(evs) <= allowed:
                return self.send_error("unknown_event", f"events phải thuộc: {sorted(allowed)}")
            new_evs = frozenset(evs)
        self.devices_filter, self.events_filter = new_devs, new_evs
        self.send_event(
            "subscribed",
            {
                "device_ids": None if new_devs is None else sorted(new_devs),
                "events": None if new_evs is None else sorted(new_evs),
            },
        )

    async def sender(self) -> None:
        while True:
            msg = await self.queue.get()
            if msg is None:
                return
            await asyncio.wait_for(self.ws.send_text(msg), timeout=10)

    async def receiver(self) -> None:
        while True:
            text = await self.ws.receive_text()
            if not self.handle_message(text):
                return

    async def guard(self) -> None:
        revalidate_s = getattr(settings, "ws_revalidate_s", 15.0)
        while True:
            wait = min(revalidate_s, max(0.0, self.ident.exp - time.time()))
            await asyncio.sleep(wait)
            if time.time() >= self.ident.exp:
                return self.close_with(4401, "token_expired", "Token đã hết hạn, hãy đăng nhập lại")
            fresh = await asyncio.to_thread(refresh_identity, self.ident)
            if fresh is None:
                return self.close_with(4401, "session_revoked", "Phiên đã bị thu hồi hoặc tài khoản đã thay đổi")
            self.ident = fresh
            if self.devices_filter is not None and fresh.devices is not None:
                self.devices_filter = self.devices_filter & fresh.devices


class Hub:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: set[Client] = set()
        self._custom_listeners: set[asyncio.Queue] = set()
        self._pending = 0
        self.stats = LatencyStats()

    def add(self, client: Client) -> None:
        with self._lock:
            self._clients.add(client)

    def remove(self, client: Client) -> None:
        with self._lock:
            self._clients.discard(client)

    def can_accept(self, user_id: int) -> bool:
        with self._lock:
            mine = sum(1 for c in self._clients if c.ident.user_id == user_id)
            max_conn = getattr(settings, "ws_max_connections", 500)
            max_per_user = getattr(settings, "ws_max_per_user", 5)
            return len(self._clients) < max_conn and mine < max_per_user

    def begin_pending(self) -> bool:
        with self._lock:
            if self._pending >= 50:
                return False
            self._pending += 1
            return True

    def end_pending(self) -> None:
        with self._lock:
            self._pending -= 1

    def count(self) -> int:
        with self._lock:
            return len(self._clients)

    def reset(self) -> None:
        with self._lock:
            self._clients.clear()
            self._custom_listeners.clear()
            self._pending = 0
        self.stats.reset()

    def publish(self, event: str, payload: dict) -> None:
        sent_at = utcnow()
        if event == "telemetry":
            self.stats.record(payload, sent_at)
        with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        device_id = payload.get("device_id")
        targets = [c for c in clients if c.wants(event, device_id)]
        if not targets:
            return
        try:
            msg = json.dumps(
                {"event": event, "data": payload, "sent_at": _iso(sent_at)},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            log.exception("không serialize được sự kiện %s", event)
            return
        for c in targets:
            try:
                c.loop.call_soon_threadsafe(c.offer, msg)
            except RuntimeError:
                self.remove(c)


hub = Hub()
