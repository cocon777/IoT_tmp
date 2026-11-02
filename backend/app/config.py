"""Application configuration loaded from environment variables / .env (TV2 + TV3)."""

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global settings for the WMS Backend (unified TV2 + TV3)."""

    # Database (TV3 & TV2)
    mysql_host: str = "mysql"
    mysql_port: int = 3306
    mysql_database: str = "wms_db"
    mysql_user: str = "wms_user"
    mysql_password: str = "CHANGE_ME"
    database_url: str | None = None
    auto_create_tables: bool = True
    telemetry_retention_days: int = 90

    # JWT & Auth (TV3 & TV2)
    jwt_secret: str = "CHANGE_ME_AT_LEAST_32_CHARS_LONG_SECRET"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    jwt_ttl_minutes: int = 30
    bcrypt_rounds: int = 12
    min_password_len: int = 8
    login_max_attempts: int = 5
    lockout_minutes: int = 15

    # MQTT & Broker Admin (TV3 & TV2)
    mqtt_host: str = "mosquitto"
    mqtt_port: int = 1883
    mqtt_backend_user: str = "backend"
    mqtt_backend_password: str = "CHANGE_ME"
    mqtt_username: str = "backend"
    mqtt_password: str = ""
    mqtt_tls: bool = False
    mqtt_ca_file: str = ""
    mqtt_client_id: str = "wms-backend"
    mqtt_dynsec_admin_user: str = "dynsec_admin"
    mqtt_dynsec_admin_password: str = "CHANGE_ME"
    broker_admin: str = "none"

    # Pump Command settings (TV2)
    command_timeout_s: int = 5
    pump_default_duration_s: int = 60
    pump_max_duration_s: int = 120

    # WebSocket /ws settings (TV2 & TV3)
    ws_allowed_origins: str = ""
    ws_auth_timeout_s: float = 5.0
    ws_revalidate_s: float = 30.0
    ws_max_connections: int = 200
    ws_max_per_user: int = 5
    ws_queue_size: int = 200

    # Ingestion & Guard settings (TV2 & TV3)
    max_payload_bytes: int = 2048
    ts_tolerance_s: int = 300
    heartbeat_timeout_s: int = 90
    rate_limit_msgs: int = 100
    rate_limit_window_s: int = 10

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def _sync_mqtt_credentials(self) -> "Settings":
        if not self.mqtt_password and self.mqtt_backend_password != "CHANGE_ME":
            self.mqtt_password = self.mqtt_backend_password
        if self.mqtt_username == "backend" and self.mqtt_backend_user != "backend":
            self.mqtt_username = self.mqtt_backend_user
        return self

    @property
    def effective_database_url(self) -> str:
        """Return explicit DATABASE_URL if set, otherwise build MySQL URL."""
        if self.database_url:
            return self.database_url
        return (
            f"mysql+pymysql://{self.mysql_user}:{self.mysql_password}"
            f"@{self.mysql_host}:{self.mysql_port}/{self.mysql_database}"
        )

    @property
    def is_sqlite(self) -> bool:
        """Return True if the effective database URL uses SQLite."""
        return self.effective_database_url.startswith("sqlite")


settings = Settings()
