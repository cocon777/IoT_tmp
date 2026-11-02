-- WMS: schema ban đầu (MySQL 8.0+). Idempotent: chạy lại không lỗi.
-- Quy ước: InnoDB, utf8mb4, giờ UTC (DATETIME), tên khóa/chỉ mục có tiền tố uq_/ix_/fk_/ck_.
-- Mỗi cột trên một dòng riêng (tests/test_schema_sync.py đọc file này để so với models.py).

CREATE TABLE IF NOT EXISTS schema_migrations (
  version     VARCHAR(64) NOT NULL,
  applied_at  DATETIME    NOT NULL DEFAULT (UTC_TIMESTAMP()),
  PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS users (
  id               INT          NOT NULL AUTO_INCREMENT,
  email            VARCHAR(255) NOT NULL,
  password_hash    VARCHAR(100) NOT NULL,
  full_name        VARCHAR(128) NOT NULL DEFAULT '',
  role             VARCHAR(16)  NOT NULL,
  status           VARCHAR(16)  NOT NULL DEFAULT 'active',
  failed_attempts  INT          NOT NULL DEFAULT 0,
  locked_until     DATETIME     NULL,
  token_version    INT          NOT NULL DEFAULT 0,
  created_at       DATETIME     NOT NULL DEFAULT (UTC_TIMESTAMP()),
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  CONSTRAINT ck_users_role   CHECK (role IN ('Admin', 'Operator', 'Viewer')),
  CONSTRAINT ck_users_status CHECK (status IN ('active', 'disabled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sites (
  id           INT          NOT NULL AUTO_INCREMENT,
  name         VARCHAR(128) NOT NULL,
  description  VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE KEY uq_sites_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- device_code nằm trong topic MQTT và là username: ASCII phân biệt hoa thường, backend chỉ cho a-z 0-9 '-'
CREATE TABLE IF NOT EXISTS devices (
  id            INT          NOT NULL AUTO_INCREMENT,
  device_code   VARCHAR(64)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  name          VARCHAR(128) NOT NULL DEFAULT '',
  site_id       INT          NULL,
  state         VARCHAR(20)  NOT NULL DEFAULT 'Registered',
  hw_version    VARCHAR(32)  NOT NULL DEFAULT '',
  fw_version    VARCHAR(32)  NOT NULL DEFAULT '',
  online        TINYINT(1)   NOT NULL DEFAULT 0,
  last_seen     DATETIME     NULL,
  created_at    DATETIME     NOT NULL DEFAULT (UTC_TIMESTAMP()),
  PRIMARY KEY (id),
  UNIQUE KEY uq_devices_code (device_code),
  KEY ix_devices_state (state),
  KEY ix_devices_site (site_id),
  CONSTRAINT fk_devices_site  FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE SET NULL,
  CONSTRAINT ck_devices_state CHECK (state IN ('Registered', 'Provisioned', 'Active', 'Offline', 'Fault', 'Maintenance', 'Decommissioned'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Chỉ lưu bản băm; mật khẩu gốc hiển thị đúng 1 lần khi cấp
CREATE TABLE IF NOT EXISTS device_credentials (
  id             INT         NOT NULL AUTO_INCREMENT,
  device_id      INT         NOT NULL,
  mqtt_username  VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  secret_hash    VARCHAR(64) NOT NULL,
  created_at     DATETIME    NOT NULL DEFAULT (UTC_TIMESTAMP()),
  revoked_at     DATETIME    NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_device_credentials_device (device_id),
  UNIQUE KEY uq_device_credentials_username (mqtt_username),
  CONSTRAINT fk_device_credentials_device FOREIGN KEY (device_id) REFERENCES devices (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Phạm vi truy cập của Operator/Viewer (Admin thấy tất cả)
CREATE TABLE IF NOT EXISTS user_devices (
  user_id    INT NOT NULL,
  device_id  INT NOT NULL,
  PRIMARY KEY (user_id, device_id),
  KEY ix_user_devices_device (device_id),
  CONSTRAINT fk_user_devices_user   FOREIGN KEY (user_id)   REFERENCES users (id)   ON DELETE CASCADE,
  CONSTRAINT fk_user_devices_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS device_configs (
  id          INT          NOT NULL AUTO_INCREMENT,
  device_id   INT          NOT NULL,
  `key`       VARCHAR(64)  NOT NULL,
  `value`     VARCHAR(255) NOT NULL,
  version     INT          NOT NULL DEFAULT 1,
  updated_by  INT          NULL,
  updated_at  DATETIME     NOT NULL DEFAULT (UTC_TIMESTAMP()),
  PRIMARY KEY (id),
  UNIQUE KEY uq_device_config_key (device_id, `key`),
  CONSTRAINT fk_device_configs_device FOREIGN KEY (device_id)  REFERENCES devices (id),
  CONSTRAINT fk_device_configs_user   FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Bảng lớn nhất. Khóa unique (device_id, boot_id, seq) loại bản tin trùng; CHECK lặp lại dải hợp lệ
-- của lớp ứng dụng (tránh dữ liệu bẩn nếu có đường ghi khác). ix_telemetry_ts phục vụ xóa theo thời gian lưu trữ.
CREATE TABLE IF NOT EXISTS telemetry (
  id            BIGINT       NOT NULL AUTO_INCREMENT,
  device_id     INT          NOT NULL,
  boot_id       VARCHAR(16)  CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  seq           BIGINT       NOT NULL,
  ts            DATETIME(3)  NOT NULL,
  received_at   DATETIME(3)  NOT NULL,
  distance_cm   FLOAT        NOT NULL,
  level_pct     FLOAT        NOT NULL,
  flow_lpm      FLOAT        NOT NULL,
  flow_total_l  DOUBLE       NOT NULL,
  pump_on       TINYINT(1)   NOT NULL,
  fault         VARCHAR(64)  NOT NULL DEFAULT '',
  rssi          INT          NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_telemetry_dedupe (device_id, boot_id, seq),
  KEY ix_telemetry_device_ts (device_id, ts),
  KEY ix_telemetry_ts (ts),
  CONSTRAINT fk_telemetry_device  FOREIGN KEY (device_id) REFERENCES devices (id),
  CONSTRAINT ck_telemetry_seq      CHECK (seq >= 0),
  CONSTRAINT ck_telemetry_distance CHECK (distance_cm BETWEEN 0 AND 1000),
  CONSTRAINT ck_telemetry_level    CHECK (level_pct BETWEEN 0 AND 100),
  CONSTRAINT ck_telemetry_flow     CHECK (flow_lpm BETWEEN 0 AND 100),
  CONSTRAINT ck_telemetry_total    CHECK (flow_total_l >= 0),
  CONSTRAINT ck_telemetry_rssi     CHECK (rssi IS NULL OR rssi BETWEEN -120 AND 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS alert_rules (
  id           INT         NOT NULL AUTO_INCREMENT,
  device_id    INT         NOT NULL,
  type         VARCHAR(32) NOT NULL,
  params_json  JSON        NOT NULL,
  severity     VARCHAR(16) NOT NULL DEFAULT 'warning',
  enabled      TINYINT(1)  NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uq_alert_rule_type (device_id, type),
  CONSTRAINT fk_alert_rules_device   FOREIGN KEY (device_id) REFERENCES devices (id),
  CONSTRAINT ck_alert_rules_type     CHECK (type IN ('LOW_LEVEL', 'HIGH_LEVEL', 'LEAK_SUSPECT', 'PUMP_NO_FLOW', 'DEVICE_OFFLINE')),
  CONSTRAINT ck_alert_rules_severity CHECK (severity IN ('warning', 'critical'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS alerts (
  id          BIGINT      NOT NULL AUTO_INCREMENT,
  device_id   INT         NOT NULL,
  rule_id     INT         NULL,
  type        VARCHAR(32) NOT NULL,
  severity    VARCHAR(16) NOT NULL,
  `value`     FLOAT       NOT NULL,
  state       VARCHAR(8)  NOT NULL,
  opened_at   DATETIME(3) NOT NULL,
  acked_by    INT         NULL,
  acked_at    DATETIME(3) NULL,
  closed_at   DATETIME(3) NULL,
  PRIMARY KEY (id),
  KEY ix_alerts_device_state (device_id, state),
  KEY ix_alerts_device_type (device_id, type, state),
  KEY ix_alerts_state_opened (state, opened_at),
  KEY ix_alerts_opened (opened_at),
  CONSTRAINT fk_alerts_device FOREIGN KEY (device_id) REFERENCES devices (id),
  CONSTRAINT fk_alerts_rule   FOREIGN KEY (rule_id)   REFERENCES alert_rules (id) ON DELETE SET NULL,
  CONSTRAINT fk_alerts_user   FOREIGN KEY (acked_by)  REFERENCES users (id) ON DELETE SET NULL,
  CONSTRAINT ck_alerts_type     CHECK (type IN ('LOW_LEVEL', 'HIGH_LEVEL', 'LEAK_SUSPECT', 'PUMP_NO_FLOW', 'DEVICE_OFFLINE')),
  CONSTRAINT ck_alerts_severity CHECK (severity IN ('warning', 'critical')),
  CONSTRAINT ck_alerts_state    CHECK (state IN ('open', 'ack', 'closed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- user_id NULL = lệnh do hệ thống (alert engine) gửi
CREATE TABLE IF NOT EXISTS commands (
  id           BIGINT       NOT NULL AUTO_INCREMENT,
  cmd_id       VARCHAR(64)  CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  device_id    INT          NOT NULL,
  user_id      INT          NULL,
  action       VARCHAR(32)  NOT NULL,
  params_json  JSON         NOT NULL,
  status       VARCHAR(16)  NOT NULL,
  sent_at      DATETIME(3)  NOT NULL,
  acked_at     DATETIME(3)  NULL,
  reason       VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE KEY uq_commands_cmd_id (cmd_id),
  KEY ix_commands_device_sent (device_id, sent_at),
  KEY ix_commands_device_status (device_id, status),
  CONSTRAINT fk_commands_device FOREIGN KEY (device_id) REFERENCES devices (id),
  CONSTRAINT fk_commands_user   FOREIGN KEY (user_id)   REFERENCES users (id) ON DELETE SET NULL,
  CONSTRAINT ck_commands_status CHECK (status IN ('sent', 'ok', 'fail', 'timeout'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- user_id NULL = hành động của hệ thống. detail có thể chứa chuỗi do người dùng nhập: phải escape khi hiển thị.
CREATE TABLE IF NOT EXISTS audit_logs (
  id           BIGINT       NOT NULL AUTO_INCREMENT,
  user_id      INT          NULL,
  action       VARCHAR(64)  NOT NULL,
  target_type  VARCHAR(32)  NOT NULL,
  target_id    VARCHAR(64)  NOT NULL,
  ip           VARCHAR(45)  NOT NULL DEFAULT '',
  detail       VARCHAR(512) NOT NULL DEFAULT '',
  created_at   DATETIME     NOT NULL DEFAULT (UTC_TIMESTAMP()),
  PRIMARY KEY (id),
  KEY ix_audit_created (created_at),
  KEY ix_audit_user_created (user_id, created_at),
  KEY ix_audit_action_created (action, created_at),
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT IGNORE INTO schema_migrations (version) VALUES ('001_init');
