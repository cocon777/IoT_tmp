"""Mosquitto Dynamic Security administration service (`broker_admin`, S11).

Provides the shared interface functions handed off to TV2 (section 2.2):
- `create_client(username, password=None)`
- `delete_client(username)`
- `disable_client(username)`
- `enable_client(username)`
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from typing import Any

import paho.mqtt.client as mqtt

from app.config import settings
from app.security.auth import hash_password

CONTROL_TOPIC = "$CONTROL/dynamic-security/v1"
RESPONSE_TOPIC = "$CONTROL/dynamic-security/v1/response"
DEVICE_BASE_ROLE = "device-base-role"
BACKEND_ROLE = "backend-role"


class BrokerAdminError(RuntimeError):
    """Raised when Mosquitto Dynamic Security returns an error or times out."""


def _device_role_name(username: str) -> str:
    """Return the per-device ACL role name for a device username."""
    return f"device-acl-{username}"


def generate_device_password(length_bytes: int = 18) -> tuple[str, str]:
    """Generate a random URL-safe plaintext password and its bcrypt hash.

    Args:
        length_bytes: Entropy bytes passed to `secrets.token_urlsafe`.

    Returns:
        tuple[str, str]: `(plaintext_password, bcrypt_password_hash)`.
            The plaintext password must only be displayed once to the caller.
    """
    raw_password = secrets.token_urlsafe(length_bytes)
    return raw_password, hash_password(raw_password)


def send_dynsec_commands(
    commands: list[dict[str, Any]],
    *,
    host: str | None = None,
    port: int | None = None,
    admin_user: str | None = None,
    admin_password: str | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Send a batch of JSON commands to `$CONTROL/dynamic-security/v1` and await response.

    Args:
        commands: List of Mosquitto Dynamic Security command dicts.
        host: Optional MQTT broker hostname (defaults to `MQTT_TEST_HOST` or `settings.mqtt_host`).
        port: Optional MQTT broker port (defaults to `settings.mqtt_port`).
        admin_user: Optional Dynamic Security admin username.
        admin_password: Optional Dynamic Security admin password.
        timeout: Seconds to wait for the response payload.

    Returns:
        list[dict[str, Any]]: List of response objects from `responses` array.

    Raises:
        BrokerAdminError: On connection failure, timeout, or command error response.
    """
    resolved_host = host or os.environ.get("MQTT_ADMIN_HOST") or settings.mqtt_host
    resolved_port = port or settings.mqtt_port
    resolved_user = admin_user or settings.mqtt_dynsec_admin_user
    resolved_pass = admin_password or settings.mqtt_dynsec_admin_password

    response_event = threading.Event()
    result_holder: dict[str, Any] = {}

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"wms-dynsec-admin-{secrets.token_hex(4)}",
    )
    client.username_pw_set(resolved_user, resolved_pass)

    def on_connect(
        c: mqtt.Client,
        _userdata: Any,
        _flags: Any,
        reason_code: Any,
        _properties: Any = None,
    ) -> None:
        if reason_code != 0:
            result_holder["connect_error"] = f"MQTT connect failed: {reason_code}"
            response_event.set()
            return
        c.subscribe(RESPONSE_TOPIC, qos=1)

    def on_subscribe(
        c: mqtt.Client,
        _userdata: Any,
        _mid: int,
        _reason_codes: Any,
        _properties: Any = None,
    ) -> None:
        payload = json.dumps({"commands": commands})
        c.publish(CONTROL_TOPIC, payload=payload, qos=1)

    def on_message(
        _c: mqtt.Client,
        _userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        try:
            result_holder["data"] = json.loads(msg.payload.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            result_holder["parse_error"] = str(exc)
        finally:
            response_event.set()

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message

    try:
        client.connect(resolved_host, resolved_port, keepalive=15)
    except Exception as exc:  # noqa: BLE001
        raise BrokerAdminError(
            f"Cannot connect to MQTT broker at {resolved_host}:{resolved_port}: {exc}"
        ) from exc

    client.loop_start()
    try:
        if not response_event.wait(timeout=timeout):
            raise BrokerAdminError(
                "Timed out waiting for response from $CONTROL/dynamic-security/v1/response"
            )
    finally:
        client.disconnect()
        client.loop_stop()

    if "connect_error" in result_holder:
        raise BrokerAdminError(result_holder["connect_error"])
    if "parse_error" in result_holder:
        raise BrokerAdminError(f"Invalid JSON from dynsec: {result_holder['parse_error']}")

    data = result_holder.get("data", {})
    responses: list[dict[str, Any]] = data.get("responses", [])
    return responses


def _build_device_role_acls(username: str) -> list[dict[str, Any]]:
    """Build exact ACL rules for a specific device username according to section 1.1."""
    return [
        {
            "acltype": "publishClientSend",
            "topic": f"wms/{username}/telemetry",
            "allow": True,
        },
        {
            "acltype": "publishClientSend",
            "topic": f"wms/{username}/status",
            "allow": True,
        },
        {
            "acltype": "publishClientSend",
            "topic": f"wms/{username}/ack",
            "allow": True,
        },
        {
            "acltype": "publishClientReceive",
            "topic": f"wms/{username}/cmd",
            "allow": True,
        },
        {
            "acltype": "publishClientReceive",
            "topic": f"wms/{username}/config",
            "allow": True,
        },
        {
            "acltype": "subscribeLiteral",
            "topic": f"wms/{username}/cmd",
            "allow": True,
        },
        {
            "acltype": "subscribeLiteral",
            "topic": f"wms/{username}/config",
            "allow": True,
        },
        {
            "acltype": "unsubscribeLiteral",
            "topic": f"wms/{username}/cmd",
            "allow": True,
        },
        {
            "acltype": "unsubscribeLiteral",
            "topic": f"wms/{username}/config",
            "allow": True,
        },
    ]


def create_client(
    username: str,
    password: str | None = None,
    *,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, str]:
    """Create a device MQTT client and assign its strict topic ACL role on the broker.

    Generates a strong random password with `secrets.token_urlsafe` if `password`
    is omitted, returns the plaintext password ONCE to the caller alongside its
    bcrypt hash (`password_hash`), and never logs the plaintext password.

    Args:
        username: Device MQTT username (`deviceId`, e.g. `'wms-001'`).
        password: Optional plaintext password; generated automatically if `None`.
        host: Optional MQTT broker hostname override.
        port: Optional MQTT broker port override.

    Returns:
        dict[str, str]: Dictionary with keys:
            - `'username'`: MQTT client username
            - `'password'`: Plaintext password (display once to Admin/device)
            - `'password_hash'`: Bcrypt hash for storing in `device_credentials.secret_hash`

    Raises:
        ValueError: If `username` is empty or contains wildcard characters.
        BrokerAdminError: If the broker rejects the creation command or times out.
    """
    if not username or any(ch in username for ch in ("+", "#", "/", " ")):
        raise ValueError("Invalid MQTT device username")

    if password is None:
        raw_password, pw_hash = generate_device_password()
    else:
        raw_password = password
        pw_hash = hash_password(password)

    role_name = _device_role_name(username)

    # Clean up any stale client/role with the same name first, then create fresh
    send_dynsec_commands(
        [
            {"command": "deleteClient", "username": username},
            {"command": "deleteRole", "rolename": role_name},
        ],
        host=host,
        port=port,
    )

    responses = send_dynsec_commands(
        [
            {
                "command": "createRole",
                "rolename": role_name,
                "acls": _build_device_role_acls(username),
            },
            {
                "command": "createClient",
                "username": username,
                "password": raw_password,
                "roles": [
                    {"rolename": DEVICE_BASE_ROLE, "priority": 1},
                    {"rolename": role_name, "priority": 10},
                ],
            },
        ],
        host=host,
        port=port,
    )

    for resp in responses:
        if "error" in resp:
            raise BrokerAdminError(
                f"Dynamic Security create_client failed for '{username}': {resp['error']}"
            )

    return {
        "username": username,
        "password": raw_password,
        "password_hash": pw_hash,
    }


def delete_client(
    username: str,
    *,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """Delete a device MQTT client and its ACL role from the broker (Decommissioned).

    Immediately kicks any active MQTT connection of `username` and prevents
    future reconnection.

    Args:
        username: Device MQTT username (`deviceId`) to revoke and delete.
        host: Optional MQTT broker hostname override.
        port: Optional MQTT broker port override.

    Returns:
        dict[str, Any]: Broker operation summary `{'username': username, 'deleted': True}`.

    Raises:
        BrokerAdminError: If the broker returns an error or times out.
    """
    role_name = _device_role_name(username)
    responses = send_dynsec_commands(
        [
            {"command": "deleteClient", "username": username},
            {"command": "deleteRole", "rolename": role_name},
        ],
        host=host,
        port=port,
    )
    if responses and "error" in responses[0]:
        raise BrokerAdminError(
            f"Dynamic Security deleteClient failed for '{username}': {responses[0]['error']}"
        )
    return {"username": username, "deleted": True}


def disable_client(
    username: str,
    *,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """Temporarily disable a device MQTT client on the broker (Maintenance state).

    Immediately disconnects the client if currently connected and rejects new
    connections until `enable_client(username)` is called.

    Args:
        username: Device MQTT username (`deviceId`) to disable.
        host: Optional MQTT broker hostname override.
        port: Optional MQTT broker port override.

    Returns:
        dict[str, Any]: Broker operation summary `{'username': username, 'enabled': False}`.

    Raises:
        BrokerAdminError: If the broker returns an error or times out.
    """
    responses = send_dynsec_commands(
        [{"command": "disableClient", "username": username}],
        host=host,
        port=port,
    )
    for resp in responses:
        if "error" in resp:
            raise BrokerAdminError(
                f"Dynamic Security disableClient failed for '{username}': {resp['error']}"
            )
    return {"username": username, "enabled": False}


def enable_client(
    username: str,
    *,
    host: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """Re-enable a previously disabled device MQTT client (Maintenance -> Active).

    Args:
        username: Device MQTT username (`deviceId`) to enable.
        host: Optional MQTT broker hostname override.
        port: Optional MQTT broker port override.

    Returns:
        dict[str, Any]: Broker operation summary `{'username': username, 'enabled': True}`.

    Raises:
        BrokerAdminError: If the broker returns an error or times out.
    """
    responses = send_dynsec_commands(
        [{"command": "enableClient", "username": username}],
        host=host,
        port=port,
    )
    for resp in responses:
        if "error" in resp:
            raise BrokerAdminError(
                f"Dynamic Security enableClient failed for '{username}': {resp['error']}"
            )
    return {"username": username, "enabled": True}


def bootstrap_broker_dynsec(
    *,
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Initialize default ACL access, `backend-role`, `device-base-role`, `backend` user, and `wms-001`."""
    send_dynsec_commands(
        [
            {
                "command": "setDefaultACLAccess",
                "acls": [
                    {"acltype": "publishClientSend", "allow": False},
                    {"acltype": "publishClientReceive", "allow": False},
                    {"acltype": "subscribe", "allow": False},
                    {"acltype": "unsubscribe", "allow": False},
                ],
            },
            {"command": "deleteClient", "username": settings.mqtt_backend_user},
            {"command": "deleteRole", "rolename": BACKEND_ROLE},
            {"command": "deleteRole", "rolename": DEVICE_BASE_ROLE},
        ],
        host=host,
        port=port,
    )

    send_dynsec_commands(
        [
            {
                "command": "createRole",
                "rolename": BACKEND_ROLE,
                "acls": [
                    {"acltype": "publishClientSend", "topic": "wms/#", "allow": True},
                    {"acltype": "publishClientReceive", "topic": "wms/#", "allow": True},
                    {"acltype": "subscribePattern", "topic": "wms/#", "allow": True},
                    {"acltype": "unsubscribePattern", "topic": "wms/#", "allow": True},
                ],
            },
            {
                "command": "createRole",
                "rolename": DEVICE_BASE_ROLE,
                "acls": [
                    {"acltype": "subscribePattern", "topic": "wms/%u/cmd", "allow": True},
                    {"acltype": "subscribePattern", "topic": "wms/%u/config", "allow": True},
                    {"acltype": "unsubscribePattern", "topic": "wms/%u/cmd", "allow": True},
                    {"acltype": "unsubscribePattern", "topic": "wms/%u/config", "allow": True},
                ],
            },
            {
                "command": "createClient",
                "username": settings.mqtt_backend_user,
                "password": settings.mqtt_backend_password,
                "roles": [{"rolename": BACKEND_ROLE, "priority": 10}],
            },
        ],
        host=host,
        port=port,
    )

    sample_user = os.environ.get("MQTT_SAMPLE_DEVICE_USER", "wms-001")
    sample_pass = os.environ.get("MQTT_SAMPLE_DEVICE_PASSWORD")
    if sample_pass:
        create_client(sample_user, sample_pass, host=host, port=port)
