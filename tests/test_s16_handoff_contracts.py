"""Unit tests verifying TV3 Section 2.2 handoff interface contracts and docstrings (S16)."""

import inspect

from app.security.auth import get_current_user
from app.security.device_guard import (
    check_device_rate_limit,
    check_payload_size,
    inspect_incoming_message,
    is_device_active,
    validate_telemetry_payload,
)
from app.security.rbac import (
    PERMISSION_MATRIX,
    can_access_device,
    require_device_access,
    require_role,
)
from app.services import audit, broker_admin


def test_section_2_2_handoff_functions_have_docstrings():
    """Every handoff function in Section 2.2 must have a non-empty docstring."""
    handoff_callables = [
        get_current_user,
        require_role,
        can_access_device,
        require_device_access,
        audit.log,
        broker_admin.create_client,
        broker_admin.delete_client,
        broker_admin.disable_client,
        broker_admin.enable_client,
        is_device_active,
        check_payload_size,
        check_device_rate_limit,
        validate_telemetry_payload,
        inspect_incoming_message,
    ]
    for fn in handoff_callables:
        doc = inspect.getdoc(fn)
        assert doc and len(doc.strip()) >= 20, f"Handoff function {fn.__name__} is missing a descriptive docstring"


def test_section_2_2_signatures():
    """Verify parameter names of key handoff functions expected by TV2 and TV4."""
    sig_can_access = inspect.signature(can_access_device)
    params_can_access = list(sig_can_access.parameters.keys())
    assert "user" in params_can_access
    assert "device_id" in params_can_access

    sig_audit = inspect.signature(audit.log)
    params_audit = list(sig_audit.parameters.keys())
    for expected in ("db", "user", "action", "target_type", "target_id", "ip", "detail"):
        assert expected in params_audit, f"audit.log missing parameter '{expected}'"

    sig_active = inspect.signature(is_device_active)
    assert "device_id" in sig_active.parameters

    assert isinstance(PERMISSION_MATRIX, dict)
    assert len(PERMISSION_MATRIX) >= 10
