-- Chính sách lưu trữ: telemetry giữ 90 ngày (khung mục 8).
-- Cần event scheduler bật: mysqld --event-scheduler=ON (đã đặt trong docker-compose.dev.yml).
-- Mỗi giờ xóa tối đa 50000 dòng để không khóa bảng lâu; chạy thường xuyên nên tự bắt kịp lượng tồn.
-- Đổi số ngày: tạo migration mới DROP EVENT rồi CREATE EVENT lại.
CREATE EVENT IF NOT EXISTS ev_telemetry_retention
  ON SCHEDULE EVERY 1 HOUR
  COMMENT 'Xoa telemetry cu hon 90 ngay'
  DO
    DELETE FROM telemetry WHERE ts < (UTC_TIMESTAMP() - INTERVAL 90 DAY) LIMIT 50000;

INSERT IGNORE INTO schema_migrations (version) VALUES ('002_telemetry_retention');
