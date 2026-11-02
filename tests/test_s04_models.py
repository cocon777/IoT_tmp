"""Unit tests for S4 security models using in-memory SQLite."""

from sqlalchemy.orm import Session

from app.models import AuditLog, DeviceStub, User, UserDevice


def test_create_user_device_and_audit_log(db_session: Session) -> None:
    """Verify User, DeviceStub, UserDevice, and AuditLog tables in SQLite."""
    device = DeviceStub(device_code="wms-001", name="Main Tank", state="Active")
    user = User(
        email="operator@wms.local",
        password_hash="$2b$12$dummyhashvalue",
        full_name="Operator One",
        role="operator",
        status="active",
    )
    db_session.add_all([device, user])
    db_session.flush()

    link = UserDevice(user_id=user.id, device_id=device.id)
    log_entry = AuditLog(
        user_id=user.id,
        action="ASSIGN_DEVICE",
        target_type="device",
        target_id=str(device.id),
        ip="127.0.0.1",
        detail="Assigned wms-001 to operator",
    )
    db_session.add_all([link, log_entry])
    db_session.commit()

    assert user.failed_attempts == 0
    assert user.locked_until is None
    assert (
        db_session.query(UserDevice)
        .filter_by(user_id=user.id, device_id=device.id)
        .count()
        == 1
    )
    assert db_session.query(AuditLog).count() == 1
