"""MQTT client subscriber and publisher for `wms/+/telemetry|status|ack` (TV2 + TV3)."""

import logging
from typing import Any

import paho.mqtt.client as mqtt

from app import ingest
from app.config import settings
from app.errors import PublishError

log = logging.getLogger("mqtt")

SUBSCRIPTIONS = [("wms/+/telemetry", 1), ("wms/+/status", 1), ("wms/+/ack", 1)]


class MqttSubscriber:
    """Persistent MQTT client subscribing to device topics and publishing commands/configs."""

    def __init__(self) -> None:
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=settings.mqtt_client_id,
            clean_session=False,
        )
        self.client.username_pw_set(settings.mqtt_username, settings.mqtt_password)
        if settings.mqtt_tls:
            self.client.tls_set(ca_certs=settings.mqtt_ca_file or None)
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def start(self) -> None:
        """Start asynchronous MQTT connection and background network loop."""
        self.client.connect_async(settings.mqtt_host, settings.mqtt_port, keepalive=30)
        self.client.loop_start()

    def stop(self) -> None:
        """Disconnect from MQTT broker and stop background network loop."""
        self.client.disconnect()
        self.client.loop_stop()

    def publish(
        self, topic: str, payload: str, qos: int = 1, retain: bool = False
    ) -> None:
        """Publish an MQTT message and wait up to 2s for PUBACK (or log no-op in test mode)."""
        if not self.client.is_connected():
            if settings.broker_admin == "none":
                log.info("[noop-mqtt] publish topic=%s payload=%s", topic, payload)
                return
            raise PublishError("Backend chưa kết nối được broker MQTT")
        try:
            info = self.client.publish(topic, payload, qos=qos, retain=retain)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise PublishError(f"Publish thất bại (rc={info.rc})")
            info.wait_for_publish(timeout=2.0)
        except (ValueError, RuntimeError) as e:
            raise PublishError(f"Publish thất bại: {e}") from e
        if not info.is_published():
            raise PublishError("Broker chưa xác nhận đã nhận lệnh")

    def _on_connect(
        self,
        client: mqtt.Client,
        _userdata: Any,
        _flags: Any,
        reason_code: Any,
        _properties: Any,
    ) -> None:
        if reason_code.is_failure:
            log.error("MQTT connect failed: %s", reason_code)
            return
        log.info("MQTT connected to %s:%s", settings.mqtt_host, settings.mqtt_port)
        client.subscribe(SUBSCRIPTIONS)

    def _on_disconnect(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        _disconnect_flags: Any,
        reason_code: Any,
        _properties: Any,
    ) -> None:
        log.warning("MQTT disconnected: %s (sẽ tự kết nối lại)", reason_code)

    def _on_message(
        self, _client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage
    ) -> None:
        try:
            ingest.handle_message(msg.topic, msg.payload, retained=bool(msg.retain))
        except Exception:
            log.exception("unhandled error processing topic=%s", msg.topic)


_instance: MqttSubscriber | None = None


def get_subscriber() -> MqttSubscriber:
    """Return the singleton MqttSubscriber instance."""
    global _instance
    if _instance is None:
        _instance = MqttSubscriber()
    return _instance
