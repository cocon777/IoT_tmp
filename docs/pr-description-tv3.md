# Mô tả Pull Request – Phân hệ TV3 (Bảo mật, Phân quyền & Triển khai)

**Tiêu đề PR đề xuất:** `feat(security-deploy): hoàn thiện phân hệ TV3 – Xác thực JWT, RBAC, Audit Log, Mosquitto DynSec/TLS và Docker Compose (S1–S16)`

**Nhánh nguồn:** `feat/s16-final-prep` → **Nhánh đích:** `main`

**Người review đề xuất (Reviewers):**
- **TV2 (Backend, CSDL và Xử lý sự kiện):** Review giao diện tích hợp bảo mật (`get_current_user`, `require_role`, `require_device_access`, `audit.log`, `broker_admin`, `is_device_active`), schema các bảng `users`, `user_devices`, `audit_logs` và các giả định ghép nối với `devices` / luồng ingest.
- **TV4 (Frontend, Giao diện thời gian thực và Trực quan hóa):** Review hợp đồng API xác thực (`/api/auth/login`, `/api/auth/logout`, `/api/auth/change-password`, `/api/me`), quản lý người dùng (`/api/users`), tra cứu nhật ký (`/api/audit-logs`), và giao thức xác thực WebSocket `WS /ws` (bản tin JSON đầu tiên trong 5 giây).

---

## 1. Phạm vi thay đổi (Scope of Changes)

1. **Hạ tầng Triển khai & Docker Compose (`deployment/`):**
   - Đóng gói 4 dịch vụ trong `deployment/docker-compose.yml`: `wms-mosquitto` (`eclipse-mosquitto:2.0`), `wms-mysql` (`mysql:8.0` có `healthcheck`, cô lập cổng `3306` trong mạng nội bộ `wms_net`), `wms-backend` (`FastAPI` chạy `--workers 1`), `wms-frontend` (`nginx:1.27-alpine`).
   - Script `deployment/scripts/make_env.sh` sinh `.env` với khóa bí mật ngẫu nhiên từ `.env.example`.
   - Script `deployment/certs/gen_certs.sh` sinh CA nội bộ (`ca.crt`) và chứng thư máy chủ (`server.crt`, `server.key`) cho MQTT over TLS (`8883`) và HTTPS Nginx (`8443`).
2. **Bảo mật MQTT Broker (`deployment/mosquitto/`, `backend/app/services/broker_admin.py`):**
   - Tắt kết nối ẩn danh (`allow_anonymous false`), thiết lập ACL theo từng thiết bị (`wms/<device_id>/telemetry|status|ack|cmd|config`).
   - Tích hợp plugin **Mosquitto Dynamic Security** (`$CONTROL/dynamic-security/v1`) qua module `broker_admin.py` (`create_client`, `delete_client`, `disable_client`, `enable_client`) để cấp/thu hồi quyền MQTT động ở runtime.
3. **Xác thực, Khóa tạm & Phân quyền RBAC (`backend/app/security/`, `backend/app/routers/`):**
   - Băm mật khẩu bằng `bcrypt`, cấp phát và xác thực JWT (`HS256`, có `jti` blacklist khi đăng xuất).
   - Khóa tạm tài khoản 15 phút sau 5 lần đăng nhập sai liên tiếp (`failed_attempts`, `locked_until`, trả mã `423 Locked`) kết hợp giới hạn tần suất theo IP.
   - Thực thi ma trận phân quyền 3 vai trò (`Admin`, `Operator`, `Viewer`) qua `require_role` và kiểm tra phạm vi thiết bị được gán trong `user_devices` qua `can_access_device` / `require_device_access`.
   - Quản lý vòng đời người dùng (`/api/users`) có bảo vệ không cho khóa/hạ quyền `Admin` đang hoạt động cuối cùng.
   - Xác thực WebSocket (`WS /ws`) bằng bản tin đầu tiên `{"type":"auth","token":"..."}` trong 5 giây và lọc sự kiện theo phạm vi thiết bị.
4. **Nhật ký Kiểm toán & Bảo vệ Luồng Ingest (`backend/app/services/audit.py`, `backend/app/security/device_guard.py`):**
   - Dịch vụ `audit.log` tự động che (`***REDACTED***`) các khóa nhạy cảm (`password`, `secret`, `token`...) và API tra cứu `GET /api/audit-logs`.
   - Bộ lọc `device_guard.py`: kiểm tra trạng thái thiết bị `is_device_active`, giới hạn kích thước payload `<= 2 KB`, tần suất `<= 12 bản tin/phút/thiết bị`, và kiểm tra miền giá trị/schema bằng `validate_telemetry_payload`.
5. **Kiểm thử Bảo mật & Tài liệu (`tests/`, `docs/`):**
   - 36 bài kiểm thử tự động `pytest` (`S04` → `S16`) và bộ kịch bản kiểm thử bảo mật xuất bằng chứng cho `F1`, `S1`–`S6`, `F8`, `S13` trong `docs/evidence/`.
   - 4 sơ đồ Mermaid + PNG trong `docs/diagrams/` và tài liệu hướng dẫn trong `README.md`.

---

## 2. Cách kiểm tra (How to Test)

```bash
# 1. Sinh biến môi trường, chứng thư TLS và mật khẩu Mosquitto
bash deployment/scripts/make_env.sh
bash deployment/certs/gen_certs.sh
bash deployment/scripts/init_mosquitto_passwd.sh

# 2. Khởi chạy 4 container
docker compose --env-file .env -f deployment/docker-compose.yml up -d --build

# 3. Khởi tạo Dynamic Security & nạp dữ liệu mẫu
bash deployment/scripts/init_mosquitto_dynsec.sh
docker exec wms-backend python /database/seed_dev.py

# 4. Chạy toàn bộ bộ kiểm thử pytest và kịch bản bảo mật
docker exec wms-backend pytest -v /app/tests
docker exec wms-backend python /app/tests/security/s14_f1_rbac_matrix.py
docker exec wms-backend python /app/tests/security/s14_s3_f8_revoke_full.py
docker exec wms-backend python /app/tests/security/s14_s5_malicious_payloads.py
```

---

## 3. Danh sách 6 hạng mục ghép nối cần đối chiếu với TV2 & TV4

1. **Thay thế model thiết bị giả lập:** Thay `backend/app/models/device_stub.py` (`DeviceStub`) bằng model `Device` thật của TV2 (giữ nguyên cột `id`, `device_code` và `state`).
2. **Gắn dependency phân quyền vào router thật:** Gắn `Depends(require_role(...))` và `Depends(require_device_access)` vào các endpoint thiết bị, telemetry, lệnh điều khiển và cảnh báo thật của TV2; gỡ bỏ router giả lập `backend/app/routers/fake_devices.py`.
3. **Ghi nhật ký kiểm toán ở các thao tác của TV2:** Gọi `audit.log(...)` tại các luồng gửi lệnh bật/tắt bơm, cập nhật cấu hình ngưỡng, đăng ký (`provision`) và đổi trạng thái vòng đời thiết bị.
4. **Đồng bộ tài khoản MQTT động:** Gọi `broker_admin.create_client`, `disable_client`, `enable_client`, `delete_client` trong luồng `provision` và đổi trạng thái thiết bị (`Active` / `Maintenance` / `Decommissioned`) của TV2.
5. **Bảo vệ luồng Ingest Telemetry của TV2:** Cho MQTT subscriber / ingest của TV2 gọi `is_device_active(device_id)`, `check_payload_size`, `check_device_rate_limit` và `validate_telemetry_payload` trước khi lưu vào bảng `telemetry`.
6. **Kiểm thử tích hợp toàn hệ thống:** Chạy lại toàn bộ kịch bản `F1`, `S1`–`S6` trên hệ thống đã ghép với giao diện của TV4 và ingest của TV2; kiểm thử `F8` với nút ESP32 thật của TV1; diễn tập kịch bản demo bước 1, 9, 10.
