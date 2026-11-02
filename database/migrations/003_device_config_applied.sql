-- Phiên bản cấu hình thiết bị báo đã áp dụng (heartbeat status.config_version). NULL = chưa từng báo.
-- Lưu ý: ALTER TABLE của MySQL không idempotent; migrate.py/initdb chỉ chạy file này đúng một lần.
ALTER TABLE devices
  ADD COLUMN config_applied_version INT NULL AFTER fw_version;

INSERT IGNORE INTO schema_migrations (version) VALUES ('003_device_config_applied');
