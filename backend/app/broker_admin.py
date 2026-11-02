"""BrokerAdmin adapter bridging TV2's lifecycle manager with TV3's `app.services.broker_admin`."""

import logging

from app.config import settings
from app.services import broker_admin as tv3_broker_admin
from app.services.broker_admin import BrokerAdminError

log = logging.getLogger("broker_admin")

BrokerError = BrokerAdminError


class BrokerAdmin:
    """Abstract interface for managing device MQTT accounts at runtime."""

    def start(self) -> None:
        """Start background broker admin connection if needed."""

    def stop(self) -> None:
        """Stop background broker admin connection if needed."""

    def create_client(self, username: str, password: str) -> None:
        """Create or update an MQTT client with device ACLs."""
        raise NotImplementedError

    def set_enabled(self, username: str, enabled: bool) -> None:
        """Enable or disable an existing MQTT device client."""
        raise NotImplementedError

    def delete_client(self, username: str) -> None:
        """Delete an MQTT device client and revoke its access."""
        raise NotImplementedError


class NoopBrokerAdmin(BrokerAdmin):
    """Development/Test no-op broker admin when Mosquitto Dynamic Security is not active."""

    def start(self) -> None:
        log.info("BROKER_ADMIN=none: using NoopBrokerAdmin")

    def create_client(self, username: str, password: str) -> None:
        log.info("[noop] create_client %s", username)

    def set_enabled(self, username: str, enabled: bool) -> None:
        log.info("[noop] set_enabled %s=%s", username, enabled)

    def delete_client(self, username: str) -> None:
        log.info("[noop] delete_client %s", username)


class DynSecBrokerAdmin(BrokerAdmin):
    """Production BrokerAdmin backed by TV3's `app.services.broker_admin` Dynamic Security client."""

    def create_client(self, username: str, password: str) -> None:
        tv3_broker_admin.create_client(username, password)

    def set_enabled(self, username: str, enabled: bool) -> None:
        if enabled:
            tv3_broker_admin.enable_client(username)
        else:
            tv3_broker_admin.disable_client(username)

    def delete_client(self, username: str) -> None:
        tv3_broker_admin.delete_client(username)


_instance: BrokerAdmin | None = None


def get_broker_admin() -> BrokerAdmin:
    """FastAPI dependency returning the configured BrokerAdmin singleton."""
    global _instance
    if _instance is None:
        _instance = (
            DynSecBrokerAdmin()
            if settings.broker_admin == "dynsec"
            else NoopBrokerAdmin()
        )
    return _instance
