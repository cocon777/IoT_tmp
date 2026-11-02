-- DỮ LIỆU MẪU CHỈ DÙNG KHI PHÁT TRIỂN/DEMO. Không chứa thông tin thật và KHÔNG chứa tài khoản người dùng
-- (mật khẩu không được commit): tạo tài khoản bằng `python -m scripts.create_user` (xem database/README.md).
-- Idempotent: chạy lại không nhân đôi dữ liệu. Nạp: mysql -u<admin> -p wms < database/seed/dev_sample.sql

INSERT IGNORE INTO sites (name, description) VALUES ('Nhà mẫu', 'Địa điểm demo');

-- Thiết bị ở trạng thái Active để thử ingest ngay. Muốn demo luồng Registered -> Provisioned -> Active
-- (F2) thì bỏ qua đoạn này và tạo thiết bị trên web.
INSERT IGNORE INTO devices (device_code, name, site_id, state, hw_version, fw_version, online)
SELECT 'wms-001', 'Bồn nước mẫu', s.id, 'Active', 'v1', '0.1.0', 0
FROM sites s WHERE s.name = 'Nhà mẫu';

-- Cấu hình mặc định (khớp mẫu ở khung mục 4.2 và device_params.DEFAULTS)
INSERT IGNORE INTO device_configs (device_id, `key`, `value`, version)
SELECT d.id, c.k, c.v, 1
FROM devices d
CROSS JOIN (
  SELECT 'sample_interval_s' AS k, '5' AS v
  UNION ALL SELECT 'tank_height_cm', '25'
  UNION ALL SELECT 'low_pct', '20'
  UNION ALL SELECT 'high_pct', '90'
  UNION ALL SELECT 'pump_max_run_s', '120'
  UNION ALL SELECT 'auto_mode', 'true'
  UNION ALL SELECT 'dry_run_s', '10'
) c
WHERE d.device_code = 'wms-001';

-- 24 giờ telemetry giả (288 mẫu, cách nhau 5 phút) để thử biểu đồ và truy vấn gộp theo mốc thời gian.
-- Mực nước dao động 25-85%, bơm chạy 8 mẫu liên tiếp mỗi giờ.
INSERT IGNORE INTO telemetry
  (device_id, boot_id, seq, ts, received_at, distance_cm, level_pct, flow_lpm, flow_total_l, pump_on, fault, rssi)
WITH RECURSIVE n (i) AS (
  SELECT 0
  UNION ALL
  SELECT i + 1 FROM n WHERE i < 287
)
SELECT d.id, 'seed', n.i,
       UTC_TIMESTAMP(3) - INTERVAL (287 - n.i) * 5 MINUTE,
       UTC_TIMESTAMP(3) - INTERVAL (287 - n.i) * 5 MINUTE,
       ROUND(25 * (1 - (55 + 30 * SIN(n.i / 30)) / 100), 1),
       ROUND(55 + 30 * SIN(n.i / 30), 1),
       IF(MOD(n.i, 60) BETWEEN 40 AND 47, 3.2, 0),
       ROUND(n.i * 0.8, 1),
       IF(MOD(n.i, 60) BETWEEN 40 AND 47, 1, 0),
       '',
       -60
FROM n
JOIN devices d ON d.device_code = 'wms-001';
