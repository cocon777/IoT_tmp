"""Pytest unit tests for S11 broker_admin password generation and input validation."""

from __future__ import annotations

import pytest

from app.security.auth import verify_password
from app.services import broker_admin


def test_generate_device_password_returns_strong_secret_and_valid_bcrypt_hash() -> None:
    """Verify generate_device_password returns URL-safe password and matching bcrypt hash."""
    raw_pw, pw_hash = broker_admin.generate_device_password()
    assert len(raw_pw) >= 20
    assert pw_hash.startswith("$2b$")
    assert verify_password(raw_pw, pw_hash) is True


def test_create_client_rejects_wildcard_or_empty_usernames() -> None:
    """Ensure create_client rejects MQTT wildcards or spaces in device username."""
    for bad_name in ("", "wms/001", "wms+001", "wms#001", "wms 001"):
        with pytest.raises(ValueError, match="Invalid MQTT device username"):
            broker_admin.create_client(bad_name)
