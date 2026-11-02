"""Security utilities, JWT authentication, lockout, RBAC, and device guard."""

from app.security.auth import (
    create_access_token,
    decode_access_token,
    get_current_user,
    hash_password,
    revoke_token,
    validate_password_strength,
    verify_dummy_password,
    verify_password,
)

# Aliases for TV2 compatibility
decode_token = decode_access_token
create_token = create_access_token
dummy_verify = verify_dummy_password
from app.security.device_guard import (
    DEVICE_RATE_LIMIT_MAX_MSGS,
    DEVICE_RATE_LIMIT_WINDOW_SECONDS,
    MAX_PAYLOAD_BYTES,
    check_device_rate_limit,
    check_payload_size,
    inspect_incoming_message,
    is_device_active,
    reset_device_rate_limits,
    validate_telemetry_payload,
)
from app.security.lockout import (
    LOCKOUT_DURATION_MINUTES,
    MAX_FAILED_ATTEMPTS,
    check_login_rate_limit,
    get_client_ip,
    is_user_temporarily_locked,
    record_failed_login,
    reset_login_attempts,
    reset_rate_limiter,
)
from app.security.rbac import (
    PERMISSION_MATRIX,
    PermissionSpec,
    can_access_device,
    require_device_access,
    require_role,
)

__all__ = [
    "DEVICE_RATE_LIMIT_MAX_MSGS",
    "DEVICE_RATE_LIMIT_WINDOW_SECONDS",
    "LOCKOUT_DURATION_MINUTES",
    "MAX_FAILED_ATTEMPTS",
    "MAX_PAYLOAD_BYTES",
    "PERMISSION_MATRIX",
    "PermissionSpec",
    "can_access_device",
    "check_device_rate_limit",
    "check_login_rate_limit",
    "check_payload_size",
    "create_access_token",
    "create_token",
    "decode_access_token",
    "decode_token",
    "dummy_verify",
    "get_client_ip",
    "get_current_user",
    "hash_password",
    "inspect_incoming_message",
    "is_device_active",
    "is_user_temporarily_locked",
    "record_failed_login",
    "require_device_access",
    "require_role",
    "reset_device_rate_limits",
    "reset_login_attempts",
    "reset_rate_limiter",
    "revoke_token",
    "validate_password_strength",
    "validate_telemetry_payload",
    "verify_password",
]
