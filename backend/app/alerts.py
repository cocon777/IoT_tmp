"""Alert engine: 5 rules, min duration, hysteresis, cooldown, and automatic safety actions (TV2 + TV3)."""

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
import statistics
import threading
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import commands, device_params
from app.audit import write_audit
from app.config import settings
from app.db import session_scope, utcnow
from app.errors import InvalidInput, PublishError
from app.events import emit
from app.lifecycle import Conflict
from app.models.device import Alert, AlertRule, Device

log = logging.getLogger("alerts")

ALERT_TYPES = (
    "LOW_LEVEL",
    "HIGH_LEVEL",
    "LEAK_SUSPECT",
    "PUMP_NO_FLOW",
    "DEVICE_OFFLINE",
)
SEVERITIES = ("warning", "critical")

RULE_DEFAULTS: dict[str, dict[str, Any]] = {
    "LOW_LEVEL": {
        "severity": "warning",
        "params": {"min_duration_s": 10, "hysteresis_pct": 5, "cooldown_s": 300},
    },
    "HIGH_LEVEL": {
        "severity": "warning",
        "params": {"min_duration_s": 0, "hysteresis_pct": 5, "cooldown_s": 300},
    },
    "LEAK_SUSPECT": {
        "severity": "critical",
        "params": {
            "window_min": 5,
            "rate_cm_per_min": 0.3,
            "settle_s": 30,
            "cooldown_s": 300,
        },
    },
    "PUMP_NO_FLOW": {
        "severity": "critical",
        "params": {
            "no_flow_s": 15,
            "rise_window_s": 60,
            "min_rise_pct": 1.0,
            "cooldown_s": 300,
        },
    },
    "DEVICE_OFFLINE": {"severity": "warning", "params": {"cooldown_s": 300}},
}
PARAM_BOUNDS = {
    "min_duration_s": (0, 3600),
    "hysteresis_pct": (0, 50),
    "cooldown_s": (0, 86400),
    "window_min": (1, 60),
    "rate_cm_per_min": (0.01, 10),
    "settle_s": (0, 600),
    "no_flow_s": (1, 600),
    "rise_window_s": (10, 1800),
    "min_rise_pct": (0, 100),
}

ACTION_MAX_AGE_S = 30
GAP_RESET_S = 120
FLOW_EPS = 0.05
SAFETY_THROTTLE_S = 30

_engine_lock = threading.Lock()
_publisher: commands.Publisher | None = None
_executor: ThreadPoolExecutor | None = None


def set_publisher(publisher: Any) -> None:
    """Register MQTT publisher used by alert engine for automatic pump actions."""
    global _publisher
    _publisher = publisher


def _submit(fn: Any) -> None:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="alert-actions")
    _executor.submit(fn)


def shutdown() -> None:
    """Stop alert action executor on application shutdown."""
    if _executor is not None:
        _executor.shutdown(wait=False, cancel_futures=True)


@dataclass(frozen=True)
class Sample:
    """Telemetry sample evaluated by the alert engine."""

    device_id: int
    ts: datetime
    level_pct: float
    flow_lpm: float
    pump_on: bool


@dataclass
class RuleView:
    """In-memory view of an AlertRule configuration."""

    id: int
    type: str
    enabled: bool
    severity: str
    params: dict[str, Any]


@dataclass
class _DevState:
    last_ts: datetime | None = None
    low_since: datetime | None = None
    high_since: datetime | None = None
    pump_off_since: datetime | None = None
    leak_win: deque[tuple[datetime, float]] = field(default_factory=deque)
    pump_on_since: datetime | None = None
    noflow_since: datetime | None = None
    rise_ref: float | None = None

    def reset_windows(self) -> None:
        self.low_since = self.high_since = self.pump_off_since = None
        self.pump_on_since = self.noflow_since = self.rise_ref = None
        self.leak_win.clear()


@dataclass
class _Ctx:
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    actions: list[Any] = field(default_factory=list)


_state: dict[int, _DevState] = defaultdict(_DevState)
_last_action: dict[tuple[int, str], float] = {}
_cache: dict[int, tuple[float, dict[str, Any], dict[str, RuleView]]] = {}
_CACHE_TTL_S = 30.0


def reset_state() -> None:
    """Clear in-memory alert engine windows and cache (used in tests)."""
    _state.clear()
    _last_action.clear()
    _cache.clear()


def invalidate(device_id: int | None = None) -> None:
    """Invalidate cached config/rules for `device_id` (or all devices if `None`)."""
    if device_id is None:
        _cache.clear()
    else:
        _cache.pop(device_id, None)


def ensure_default_rules(s: Session, device_id: int) -> None:
    """Create default AlertRule rows for `device_id` if missing."""
    have = set(
        s.scalars(select(AlertRule.type).where(AlertRule.device_id == device_id))
    )
    for type_, d in RULE_DEFAULTS.items():
        if type_ in have:
            continue
        try:
            with s.begin_nested():
                s.add(
                    AlertRule(
                        device_id=device_id,
                        type=type_,
                        params_json=json.dumps(d["params"]),
                        severity=d["severity"],
                        enabled=True,
                    )
                )
        except IntegrityError:
            pass


def load_rules(s: Session, device_id: int) -> dict[str, RuleView]:
    """Load all AlertRule rows for `device_id` (creating defaults if needed)."""
    ensure_default_rules(s, device_id)
    out: dict[str, RuleView] = {}
    for r in s.scalars(select(AlertRule).where(AlertRule.device_id == device_id)):
        if r.type not in RULE_DEFAULTS:
            continue
        base = RULE_DEFAULTS[r.type]["params"]
        try:
            stored = json.loads(r.params_json or "{}")
        except ValueError:
            stored = {}
        params = {**base, **{k: v for k, v in stored.items() if k in base}}
        out[r.type] = RuleView(r.id, r.type, bool(r.enabled), r.severity, params)
    return out


def _context(
    s: Session, device_id: int
) -> tuple[dict[str, Any], dict[str, RuleView]]:
    hit = _cache.get(device_id)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL_S:
        return hit[1], hit[2]
    cfg, rules = device_params.get_config(s, device_id), load_rules(s, device_id)
    _cache[device_id] = (time.monotonic(), cfg, rules)
    return cfg, rules


def _clean_params(type_: str, params: dict[str, Any]) -> dict[str, Any]:
    allowed = RULE_DEFAULTS[type_]["params"]
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k not in allowed:
            raise InvalidInput(f"{type_}: tham số '{k}' không hợp lệ")
        lo, hi = PARAM_BOUNDS[k]
        if not (lo <= v <= hi):
            raise InvalidInput(f"{type_}.{k} phải trong khoảng {lo}..{hi}")
        out[k] = int(v) if float(v).is_integer() else float(v)
    return out


def apply_rule_updates(
    s: Session,
    dev: Device,
    updates: list[dict[str, Any]],
    *,
    actor_id: int | None,
    ip: str,
) -> dict[str, RuleView]:
    """Validate and apply updates to alert rules for `dev`."""
    seen = [u["type"] for u in updates]
    if len(set(seen)) != len(seen):
        raise InvalidInput("Mỗi loại quy tắc chỉ được nêu một lần")
    ensure_default_rules(s, dev.id)
    s.flush()
    rows = {
        r.type: r
        for r in s.scalars(select(AlertRule).where(AlertRule.device_id == dev.id))
    }
    changes = []
    for u in updates:
        row = rows[u["type"]]
        if u.get("severity") is not None:
            if u["severity"] not in SEVERITIES:
                raise InvalidInput("severity phải là warning hoặc critical")
            row.severity = u["severity"]
            changes.append(f"{u['type']} severity={u['severity']}")
        if u.get("enabled") is not None:
            row.enabled = bool(u["enabled"])
            changes.append(f"{u['type']} enabled={row.enabled}")
        if u.get("params"):
            clean = _clean_params(u["type"], u["params"])
            row.params_json = json.dumps(
                {**json.loads(row.params_json or "{}"), **clean}
            )
            changes.append(f"{u['type']} params={clean}")
    write_audit(
        s, actor_id, "alert_rule.update", "device", dev.id, ip, "; ".join(changes)
    )
    s.commit()
    invalidate(dev.id)
    return load_rules(s, dev.id)


def _iso(dt: datetime | None) -> str | None:
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def alert_event(a: Alert, dev: Device) -> dict[str, Any]:
    """Format Alert ORM record as real-time WebSocket event dictionary."""
    return {
        "alert_id": a.id,
        "device_id": dev.id,
        "device_code": dev.device_code,
        "type": a.type,
        "severity": a.severity,
        "value": a.value,
        "state": a.state,
        "opened_at": _iso(a.opened_at),
        "acked_at": _iso(a.acked_at),
        "closed_at": _iso(a.closed_at),
    }


def _raise(
    s: Session,
    ctx: _Ctx,
    dev: Device,
    rule: RuleView,
    value: float,
    ts: datetime,
) -> Alert | None:
    active = s.scalars(
        select(Alert.id).where(
            Alert.device_id == dev.id,
            Alert.type == rule.type,
            Alert.state.in_(("open", "ack")),
        )
    ).first()
    if active:
        return None
    last_closed = s.scalars(
        select(Alert.closed_at)
        .where(
            Alert.device_id == dev.id,
            Alert.type == rule.type,
            Alert.state == "closed",
        )
        .order_by(Alert.closed_at.desc())
        .limit(1)
    ).first()
    if (
        last_closed
        and (ts - last_closed).total_seconds() < rule.params.get("cooldown_s", 300)
    ):
        return None
    a = Alert(
        device_id=dev.id,
        rule_id=rule.id,
        type=rule.type,
        severity=rule.severity,
        value=float(value),
        state="open",
        opened_at=ts,
    )
    s.add(a)
    s.flush()
    write_audit(
        s,
        None,
        "alert.open",
        "alert",
        a.id,
        "system",
        f"device={dev.device_code} type={rule.type} value={float(value):.2f}",
    )
    ctx.events.append(("alert", alert_event(a, dev)))
    return a


def _clear(
    s: Session, ctx: _Ctx, dev: Device, type_: str, ts: datetime
) -> None:
    for a in s.scalars(
        select(Alert).where(
            Alert.device_id == dev.id,
            Alert.type == type_,
            Alert.state.in_(("open", "ack")),
        )
    ).all():
        a.state, a.closed_at = "closed", ts
        s.flush()
        write_audit(
            s,
            None,
            "alert.auto_close",
            "alert",
            a.id,
            "system",
            f"device={dev.device_code} type={type_}",
        )
        ctx.events.append(("alert", alert_event(a, dev)))


def _throttled(device_id: int, name: str) -> bool:
    now, key = time.monotonic(), (device_id, name)
    if now - _last_action.get(key, -1e9) < SAFETY_THROTTLE_S:
        return True
    _last_action[key] = now
    return False


def _pump_action(
    device_id: int, value: str, duration_s: int | None, source: str
) -> Any:
    def run() -> None:
        publisher = _publisher
        if publisher is None:
            log.warning("không có publisher, bỏ qua %s device=%s", source, device_id)
            return
        try:
            with session_scope() as s:
                dev = s.get(Device, device_id)
                if dev is not None:
                    commands.send_pump_command(
                        s,
                        publisher,
                        dev,
                        value=value,
                        duration_s=duration_s,
                        actor_id=None,
                        ip="system",
                        source=source,
                    )
        except (Conflict, InvalidInput, PublishError) as e:
            log.warning(
                "lệnh tự động %s bị từ chối device=%s: %s", source, device_id, e
            )
        except Exception:
            log.exception("lỗi lệnh tự động %s device=%s", source, device_id)

    return run


def _set_fault(s: Session, ctx: _Ctx, dev: Device, reason: str) -> None:
    if dev.state != "Active":
        return
    dev.state = "Fault"
    write_audit(
        s,
        None,
        "device.state",
        "device",
        dev.id,
        "system",
        f"Active->Fault ({reason})",
    )
    ctx.events.append(
        (
            "device_state",
            {
                "device_code": dev.device_code,
                "device_id": dev.id,
                "state": "Fault",
                "online": dev.online,
                "fw_version": dev.fw_version,
            },
        )
    )


def _rule_low(
    s: Session,
    ctx: _Ctx,
    dev: Device,
    rule: RuleView | None,
    cfg: dict[str, Any],
    st: _DevState,
    smp: Sample,
    fresh: bool,
) -> None:
    if rule is None or not rule.enabled:
        return
    p, low = rule.params, float(cfg["low_pct"])
    if smp.level_pct < low:
        st.low_since = st.low_since or smp.ts
        if (smp.ts - st.low_since).total_seconds() >= p["min_duration_s"]:
            alert = _raise(s, ctx, dev, rule, smp.level_pct, smp.ts)
            if alert and cfg["auto_mode"] and fresh and dev.state == "Active":
                duration = min(
                    settings.pump_default_duration_s, int(cfg["pump_max_run_s"])
                )
                ctx.actions.append(
                    _pump_action(dev.id, "on", duration, "auto:LOW_LEVEL")
                )
    else:
        st.low_since = None
        if smp.level_pct > low + p["hysteresis_pct"]:
            _clear(s, ctx, dev, "LOW_LEVEL", smp.ts)


def _rule_high(
    s: Session,
    ctx: _Ctx,
    dev: Device,
    rule: RuleView | None,
    cfg: dict[str, Any],
    st: _DevState,
    smp: Sample,
    fresh: bool,
) -> None:
    if rule is None or not rule.enabled:
        return
    p, high = rule.params, float(cfg["high_pct"])
    if smp.level_pct > high:
        st.high_since = st.high_since or smp.ts
        if (smp.ts - st.high_since).total_seconds() >= p["min_duration_s"]:
            _raise(s, ctx, dev, rule, smp.level_pct, smp.ts)
            if smp.pump_on and fresh and not _throttled(dev.id, "high_off"):
                ctx.actions.append(
                    _pump_action(dev.id, "off", None, "auto:HIGH_LEVEL")
                )
    else:
        st.high_since = None
        if smp.level_pct < high - p["hysteresis_pct"]:
            _clear(s, ctx, dev, "HIGH_LEVEL", smp.ts)


def _drop_rate_cm_per_min(
    win: deque[tuple[datetime, float]], tank_height_cm: float
) -> float | None:
    n = len(win)
    k = max(3, min(5, n // 4))
    if n < 2 * k:
        return None
    pts = list(win)
    first, last = pts[:k], pts[-k:]
    minutes = (last[k // 2][0] - first[k // 2][0]).total_seconds() / 60
    if minutes <= 0:
        return None
    drop_pct = statistics.median(v for _, v in first) - statistics.median(
        v for _, v in last
    )
    return drop_pct / 100.0 * tank_height_cm / minutes


def _rule_leak(
    s: Session,
    ctx: _Ctx,
    dev: Device,
    rule: RuleView | None,
    cfg: dict[str, Any],
    st: _DevState,
    smp: Sample,
    _fresh: bool,
) -> None:
    if rule is None or not rule.enabled:
        return
    p = rule.params
    if smp.pump_on:
        st.leak_win.clear()
        st.pump_off_since = None
        return
    st.pump_off_since = st.pump_off_since or smp.ts
    if (smp.ts - st.pump_off_since).total_seconds() < p["settle_s"]:
        return
    win = st.leak_win
    win.append((smp.ts, smp.level_pct))
    horizon = p["window_min"] * 60 + 2 * float(cfg["sample_interval_s"])
    while (smp.ts - win[0][0]).total_seconds() > horizon:
        win.popleft()
    if (win[-1][0] - win[0][0]).total_seconds() < p["window_min"] * 60:
        return
    rate = _drop_rate_cm_per_min(win, float(cfg["tank_height_cm"]))
    if rate is None:
        return
    if rate > p["rate_cm_per_min"]:
        _raise(s, ctx, dev, rule, rate, smp.ts)
    elif rate <= p["rate_cm_per_min"] / 2:
        _clear(s, ctx, dev, "LEAK_SUSPECT", smp.ts)


def _rule_no_flow(
    s: Session,
    ctx: _Ctx,
    dev: Device,
    rule: RuleView | None,
    cfg: dict[str, Any],
    st: _DevState,
    smp: Sample,
    fresh: bool,
) -> None:
    if rule is None or not rule.enabled:
        return
    p = rule.params
    if not smp.pump_on:
        st.pump_on_since = st.noflow_since = st.rise_ref = None
        return
    if st.pump_on_since is None:
        st.pump_on_since, st.rise_ref = smp.ts, smp.level_pct
    if smp.flow_lpm <= FLOW_EPS:
        st.noflow_since = st.noflow_since or smp.ts
    else:
        st.noflow_since = None
    dry = (
        st.noflow_since is not None
        and (smp.ts - st.noflow_since).total_seconds() >= p["no_flow_s"]
    )
    gain = smp.level_pct - (st.rise_ref or 0.0)
    stagnant = (
        (smp.ts - st.pump_on_since).total_seconds() >= p["rise_window_s"]
        and gain < p["min_rise_pct"]
        and smp.level_pct < float(cfg["high_pct"])
    )
    if not (dry or stagnant):
        return
    _raise(s, ctx, dev, rule, smp.flow_lpm if dry else gain, smp.ts)
    if fresh and dev.state == "Active":
        _set_fault(s, ctx, dev, "PUMP_NO_FLOW")
        ctx.actions.append(_pump_action(dev.id, "off", None, "auto:PUMP_NO_FLOW"))


def _evaluate(s: Session, ctx: _Ctx, smp: Sample) -> None:
    dev = s.get(Device, smp.device_id)
    if dev is None or dev.state not in ("Active", "Fault"):
        return
    cfg, rules = _context(s, dev.id)
    st = _state[dev.id]
    if st.last_ts is not None:
        if smp.ts <= st.last_ts:
            return
        if (smp.ts - st.last_ts).total_seconds() > GAP_RESET_S:
            st.reset_windows()
    st.last_ts = smp.ts
    fresh = (utcnow() - smp.ts).total_seconds() <= ACTION_MAX_AGE_S
    for fn, type_ in (
        (_rule_low, "LOW_LEVEL"),
        (_rule_high, "HIGH_LEVEL"),
        (_rule_leak, "LEAK_SUSPECT"),
        (_rule_no_flow, "PUMP_NO_FLOW"),
    ):
        fn(s, ctx, dev, rules.get(type_), cfg, st, smp, fresh)


def _flush(ctx: _Ctx) -> None:
    for event, payload in ctx.events:
        emit(event, payload)
    for action in ctx.actions:
        _submit(action)


def evaluate(smp: Sample) -> None:
    """Evaluate all alert rules against telemetry sample `smp` after commit."""
    ctx = _Ctx()
    try:
        with _engine_lock, session_scope() as s:
            _evaluate(s, ctx, smp)
    except Exception:
        log.exception("alert engine lỗi (device=%s)", smp.device_id)
        return
    _flush(ctx)


def on_device_offline(device_id: int, ts: datetime | None = None) -> None:
    """Trigger `DEVICE_OFFLINE` alert when device loses heartbeat or sends LWT."""
    ts, ctx = ts or utcnow(), _Ctx()
    try:
        with _engine_lock, session_scope() as s:
            dev = s.get(Device, device_id)
            if dev is None:
                return
            _, rules = _context(s, device_id)
            _state.pop(device_id, None)
            rule = rules.get("DEVICE_OFFLINE")
            if rule and rule.enabled:
                silent = (
                    (ts - dev.last_seen).total_seconds() if dev.last_seen else 0.0
                )
                _raise(s, ctx, dev, rule, max(silent, 0.0), ts)
    except Exception:
        log.exception("alert engine lỗi khi xử lý offline (device=%s)", device_id)
        return
    _flush(ctx)


def on_device_online(device_id: int, ts: datetime | None = None) -> None:
    """Auto-close active `DEVICE_OFFLINE` alert when device reconnects."""
    ts, ctx = ts or utcnow(), _Ctx()
    try:
        with _engine_lock, session_scope() as s:
            dev = s.get(Device, device_id)
            if dev is not None:
                _clear(s, ctx, dev, "DEVICE_OFFLINE", ts)
    except Exception:
        log.exception("alert engine lỗi khi xử lý online (device=%s)", device_id)
        return
    _flush(ctx)
