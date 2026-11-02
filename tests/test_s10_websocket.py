"""Unit and API tests for S10 WebSocket JWT authentication and event scope filtering."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.main import app
from app.models import DeviceStub, User, UserDevice
from app.routers import ws as ws_module
from app.security.auth import create_access_token, hash_password


def _seed_ws_actors(db: Session) -> dict[str, object]:
    dev1 = DeviceStub(id=1, device_code="wms-001", name="Tank A", state="Active")
    dev2 = DeviceStub(id=2, device_code="wms-002", name="Tank B", state="Active")
    op_a = User(
        email="op_a@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Operator A",
        role="operator",
        status="active",
    )
    op_b = User(
        email="op_b@wms.io",
        password_hash=hash_password("Pass1234"),
        full_name="Operator B",
        role="operator",
        status="active",
    )
    db.add_all([dev1, dev2, op_a, op_b])
    db.flush()
    db.add_all(
        [
            UserDevice(user_id=op_a.id, device_id=dev1.id),
            UserDevice(user_id=op_b.id, device_id=dev2.id),
        ]
    )
    db.commit()
    return {
        "op_a": op_a,
        "op_b": op_b,
        "token_a": create_access_token(op_a.id, op_a.role),
        "token_b": create_access_token(op_b.id, op_b.role),
    }


def test_ws_rejects_unauthenticated_invalid_or_expired_token(
    db_session: Session, override_get_db: None
) -> None:
    """WebSocket closes with 1008 when first message is not valid auth or token is expired."""
    ctx = _seed_ws_actors(db_session)
    op_a: User = ctx["op_a"]  # type: ignore[assignment]
    client = TestClient(app)

    # 1. First message is not type="auth"
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "ping"})
        err = ws.receive_json()
        assert err["type"] == "auth_error"
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008

    # 2. Expired token
    expired = create_access_token(
        op_a.id, op_a.role, expires_delta=timedelta(seconds=-10)
    )
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "auth", "token": expired})
        err = ws.receive_json()
        assert err["type"] == "auth_error"
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008


def test_ws_timeout_when_no_auth_message_sent(
    db_session: Session,
    override_get_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WebSocket closes with 1008 if client sends no auth message within timeout."""
    _seed_ws_actors(db_session)
    monkeypatch.setattr(ws_module, "WS_AUTH_TIMEOUT_SECONDS", 0.15)
    client = TestClient(app)

    with client.websocket_connect("/ws") as ws:
        err = ws.receive_json()
        assert err["type"] == "auth_error"
        assert "timeout" in err["detail"].lower()
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
        assert exc_info.value.code == 1008


def test_ws_scopes_events_per_user_and_closes_when_account_locked(
    db_session: Session, override_get_db: None
) -> None:
    """Operator A only receives device 1 events; Operator B only receives device 2 events;
    locking Operator A closes the active WebSocket connection.
    """
    ctx = _seed_ws_actors(db_session)
    op_a: User = ctx["op_a"]  # type: ignore[assignment]
    client = TestClient(app)

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        ws_a.send_json({"type": "auth", "token": ctx["token_a"]})
        assert ws_a.receive_json()["type"] == "auth_ok"

        ws_b.send_json({"type": "auth", "token": ctx["token_b"]})
        assert ws_b.receive_json()["type"] == "auth_ok"

        # Trigger simulated periodic events across device 1 and device 2
        ws_a.send_json({"type": "simulate_tick"})
        ev_a = ws_a.receive_json()
        assert ev_a["device_id"] == 1
        assert ev_a["device_code"] == "wms-001"

        ws_b.send_json({"type": "simulate_tick"})
        ev_b = ws_b.receive_json()
        assert ev_b["device_id"] == 2
        assert ev_b["device_code"] == "wms-002"

        # Lock Operator A in database -> next message closes WebSocket with 1008
        op_a.status = "locked"
        db_session.add(op_a)
        db_session.commit()

        ws_a.send_json({"type": "ping"})
        err = ws_a.receive_json()
        assert err["type"] == "error"
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws_a.receive_json()
        assert exc_info.value.code == 1008
