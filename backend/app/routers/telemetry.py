"""Real Telemetry query and CSV export router (TV2 + TV3 RBAC)."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import io
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import Integer, cast, func, literal_column, select
from sqlalchemy.orm import Session

from app import lifecycle
from app.audit import write_audit
from app.db import SessionLocal, engine, get_db, utcnow
from app.errors import InvalidInput
from app.models.device import Telemetry
from app.models.user import User
from app.security.lockout import get_client_ip
from app.security.rbac import (
    PERMISSION_MATRIX,
    require_device_access,
    require_role,
)

router = APIRouter(prefix="/api/devices/{device_id}/telemetry", tags=["telemetry"])

Interval = Literal["auto", "raw", "1m", "5m", "15m", "1h"]
BUCKET_SECONDS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600}
MAX_RANGE = timedelta(days=90)
MAX_RAW_RANGE = timedelta(hours=6)
MAX_EXPORT_RANGE = timedelta(days=31)
RAW_LIMIT = 5000


class TelemetryPoint(BaseModel):
    """Single raw or aggregated telemetry data point."""

    ts: datetime
    level_pct: float
    flow_lpm: float
    flow_total_l: float
    pump_on: bool
    n: int = 1


class TelemetrySeries(BaseModel):
    """Time-series telemetry query response."""

    device_id: int
    interval: str
    start: datetime
    end: datetime
    points: list[TelemetryPoint]


class LatestOut(BaseModel):
    """Most recent telemetry measurement for a device."""

    ts: datetime
    received_at: datetime
    distance_cm: float
    level_pct: float
    flow_lpm: float
    flow_total_l: float
    pump_on: bool
    fault: str
    rssi: int | None


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc)


def _naive_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _resolve_range(
    from_: datetime | None, to: datetime | None, max_range: timedelta
) -> tuple[datetime, datetime]:
    end = _naive_utc(to) if to else utcnow()
    start = _naive_utc(from_) if from_ else end - timedelta(hours=1)
    if start >= end:
        raise InvalidInput("'from' phải nhỏ hơn 'to'")
    if end - start > max_range:
        raise InvalidInput(f"Khoảng thời gian tối đa {max_range.days} ngày")
    return start, end


def _auto_interval(span: timedelta) -> str:
    if span <= timedelta(hours=2):
        return "raw"
    if span <= timedelta(hours=36):
        return "5m"
    return "1h"


def _epoch(col: object, db: Session) -> object:
    dialect_name = db.get_bind().dialect.name
    if dialect_name == "mysql":
        return func.unix_timestamp(col, type_=Integer)
    return cast(func.strftime("%s", col), Integer)


@router.get(
    "",
    response_model=TelemetrySeries,
    dependencies=[
        Depends(require_role(*PERMISSION_MATRIX["telemetry:view"].allowed_roles)),
        Depends(require_device_access),
    ],
)
def query_telemetry(
    device_id: int,
    from_: datetime | None = Query(None, alias="from"),
    to: datetime | None = None,
    interval: Interval = "auto",
    db: Session = Depends(get_db),
) -> TelemetrySeries:
    """Query raw or time-bucketed telemetry series for `device_id`."""
    dev = lifecycle.get_device(db, device_id)
    start, end = _resolve_range(from_, to, MAX_RANGE)
    resolved_interval: str = (
        _auto_interval(end - start) if interval == "auto" else interval
    )
    if resolved_interval == "raw" and end - start > MAX_RAW_RANGE:
        raise InvalidInput(
            "Dữ liệu thô chỉ cho khoảng tối đa 6 giờ; hãy chọn interval 1m/5m/15m/1h"
        )

    cond = (
        Telemetry.device_id == dev.id,
        Telemetry.ts >= start,
        Telemetry.ts < end,
    )
    if resolved_interval == "raw":
        rows = db.execute(
            select(
                Telemetry.ts,
                Telemetry.level_pct,
                Telemetry.flow_lpm,
                Telemetry.flow_total_l,
                Telemetry.pump_on,
            )
            .where(*cond)
            .order_by(Telemetry.ts)
            .limit(RAW_LIMIT)
        ).all()
        points = [
            TelemetryPoint(
                ts=_utc(r.ts),
                level_pct=r.level_pct,
                flow_lpm=r.flow_lpm,
                flow_total_l=r.flow_total_l,
                pump_on=bool(r.pump_on),
            )
            for r in rows
        ]
    else:
        size = literal_column(
            str(BUCKET_SECONDS[resolved_interval]), type_=Integer
        )
        bucket = ((_epoch(Telemetry.ts, db) // size) * size).label("bucket")
        rows = db.execute(
            select(
                bucket,
                func.avg(Telemetry.level_pct),
                func.avg(Telemetry.flow_lpm),
                func.max(Telemetry.flow_total_l),
                func.max(Telemetry.pump_on),
                func.count(),
            )
            .where(*cond)
            .group_by(bucket)
            .order_by(bucket)
        ).all()
        points = [
            TelemetryPoint(
                ts=datetime.fromtimestamp(int(r[0]), tz=timezone.utc),
                level_pct=float(r[1]),
                flow_lpm=float(r[2]),
                flow_total_l=float(r[3]),
                pump_on=bool(r[4]),
                n=int(r[5]),
            )
            for r in rows
        ]
    return TelemetrySeries(
        device_id=dev.id,
        interval=resolved_interval,
        start=_utc(start),
        end=_utc(end),
        points=points,
    )


@router.get(
    "/latest",
    response_model=LatestOut | None,
    dependencies=[
        Depends(require_role(*PERMISSION_MATRIX["telemetry:view"].allowed_roles)),
        Depends(require_device_access),
    ],
)
def latest(
    device_id: int,
    db: Session = Depends(get_db),
) -> LatestOut | None:
    """Return the latest telemetry sample for `device_id`."""
    dev = lifecycle.get_device(db, device_id)
    row = db.scalars(
        select(Telemetry)
        .where(Telemetry.device_id == dev.id)
        .order_by(Telemetry.ts.desc(), Telemetry.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    return LatestOut(
        ts=_utc(row.ts),
        received_at=_utc(row.received_at),
        distance_cm=row.distance_cm,
        level_pct=row.level_pct,
        flow_lpm=row.flow_lpm,
        flow_total_l=row.flow_total_l,
        pump_on=row.pump_on,
        fault=row.fault,
        rssi=row.rssi,
    )


def _csv_safe(value: str) -> str:
    return "'" + value if value and value[0] in "=+-@\t\r" else value


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@router.get(
    "/export",
    dependencies=[
        Depends(
            require_role(*PERMISSION_MATRIX["telemetry:export_csv"].allowed_roles)
        ),
        Depends(require_device_access),
    ],
)
def export_csv(
    device_id: int,
    request: Request,
    from_: datetime | None = Query(None, alias="from"),
    to: datetime | None = None,
    current_user: User = Depends(
        require_role(*PERMISSION_MATRIX["telemetry:export_csv"].allowed_roles)
    ),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Export telemetry rows as CSV (up to 31 days) and record an audit log entry."""
    dev = lifecycle.get_device(db, device_id)
    start, end = _resolve_range(from_, to, MAX_EXPORT_RANGE)
    write_audit(
        db,
        current_user.id,
        "telemetry.export",
        "device",
        dev.id,
        get_client_ip(request),
        f"{_iso(start)}..{_iso(end)}",
    )
    db.commit()
    dev_id, code = dev.id, dev.device_code
    columns = [
        Telemetry.ts,
        Telemetry.received_at,
        Telemetry.boot_id,
        Telemetry.seq,
        Telemetry.distance_cm,
        Telemetry.level_pct,
        Telemetry.flow_lpm,
        Telemetry.flow_total_l,
        Telemetry.pump_on,
        Telemetry.fault,
        Telemetry.rssi,
    ]

    stmt = (
        select(*columns)
        .where(
            Telemetry.device_id == dev_id,
            Telemetry.ts >= start,
            Telemetry.ts < end,
        )
        .order_by(Telemetry.ts)
    )
    rows = db.execute(stmt).all()

    def generate():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "ts",
                "received_at",
                "boot_id",
                "seq",
                "distance_cm",
                "level_pct",
                "flow_lpm",
                "flow_total_l",
                "pump_on",
                "fault",
                "rssi",
            ]
        )
        for r in rows:
            w.writerow(
                [
                    _iso(r.ts),
                    _iso(r.received_at),
                    _csv_safe(r.boot_id),
                    r.seq,
                    r.distance_cm,
                    r.level_pct,
                    r.flow_lpm,
                    r.flow_total_l,
                    int(r.pump_on),
                    _csv_safe(r.fault),
                    "" if r.rssi is None else r.rssi,
                ]
            )
            if buf.tell() > 64_000:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
        yield buf.getvalue()

    name = f"{code}_{start:%Y%m%d%H%M}_{end:%Y%m%d%H%M}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
