# Tiến độ agent – TV3

| Bước | Trạng thái | Ghi chú |
| --- | --- | --- |
| S0 | DONE | Đã xác minh đủ công cụ (`docker`, `docker compose`, `python` 3.13.3, `git`, `openssl`, `mosquitto_*`, `curl`), cấu hình Git và khởi tạo repo |
| S1 | DONE | Đã tạo khung repo, `.gitignore`, `.env.example`, `make_env.sh`, đẩy remote GitHub và bật branch protection cho `main` |
| S2 | DONE | Đã dựng `deployment/docker-compose.yml` (4 dịch vụ: `mosquitto`, `mysql` healthy, `backend` `--workers 1`, `frontend`), không mở cổng 3306 ra host, `/health` trả 200 |
| S3 | DONE | Đã cấu hình Mosquitto `allow_anonymous false`, `password_file`, `acl_file`, script `s03_broker_acl.sh` đạt 5/5 PASS, lưu bằng chứng `docs/evidence/s4-acl-log.txt` |
| S4 | DONE | Đã dựng `config.py`, `db.py`, các model `User`, `UserDevice`, `AuditLog`, `DeviceStub`, `seed_dev.py`, xác minh bảng trong MySQL, `/docs` 200 và `pytest` xanh |
| S5 | DONE | Đã hoàn tất đăng nhập, JWT (PyJWT), băm mật khẩu (`bcrypt`), `get_current_user`, lưu bằng chứng `docs/evidence/s2-401.txt` và qua REVIEW GATE |
| S6 | DONE | Đã hoàn tất khóa tạm 15 phút sau 5 lần sai (`failed_attempts`, `locked_until`), giới hạn tần suất theo IP, lưu `docs/evidence/s6-lockout.txt` và qua REVIEW GATE |
| S7 | DONE | Đã hoàn tất `security/rbac.py` (`PERMISSION_MATRIX`, `require_role`, `can_access_device`, `require_device_access`), stub `routers/fake_devices.py`, lưu `docs/evidence/s1-cross-device.txt` và qua REVIEW GATE |
| S8 | DONE | Đã cài đặt API `/api/users` (`GET`, `POST`, `PATCH`), gán/bỏ gán thiết bị, bảo vệ Admin cuối cùng, `pytest` xanh |
| S9 | DONE | Đã cài đặt `services/audit.py` (`audit.log`), tích hợp vào auth/user/RBAC, API `GET /api/audit-logs` có lọc và phân trang, `pytest` xanh |
| S10 | DONE | Đã cài đặt `WS /ws` xác thực bằng bản tin đầu tiên trong 5s, lọc sự kiện qua `can_access_device`, đóng kết nối khi tài khoản bị khóa, `pytest` xanh |
| S11 | DONE | Đã hoàn tất Mosquitto Dynamic Security, `services/broker_admin.py`, `docs/notes/dynsec.md`, lưu `docs/evidence/s3-broker-revoke.txt` và qua REVIEW GATE |
| S12 | DONE | Đã cài đặt `is_device_active`, `check_payload_size` (2 KB), `check_device_rate_limit`, subscriber thử `tests/tools/guard_probe.py`, `pytest` xanh |
| S13 | DONE | Đã hoàn tất TLS 8883 cho Mosquitto, HTTPS 8443 cho Nginx, `docs/notes/tls-for-esp32.md`, xác minh `s13_tls_verify.sh`, ảnh `docs/evidence/s-tls-wireshark.png` và qua REVIEW GATE |
| S14 | DONE | Đã hoàn tất bộ kiểm thử `F1`, `S1`–`S6`, `F8`, `payloads_s05.json`, `pytest` 34/34 PASS, lưu đủ bằng chứng trong `docs/evidence/` và qua CP-S14-A |
| S15 | DONE | Đã tạo 4 sơ đồ Mermaid + 4 ảnh PNG trong `docs/diagrams/`, bản nháp dàn ý báo cáo `docs/report-draft-tv3.md`, cập nhật `README.md`, xác minh clone sạch + `docker compose up` và qua CP-S15-A |
| S16 | WAITING_USER (CP-S16-A) | Đã kiểm tra docstring & test cho toàn bộ hàm giao diện mục 2.2 (`36 passed`), hoàn thiện danh sách 6 mục ghép nối, soạn mô tả PR `docs/pr-description-tv3.md`; chờ người dùng xác nhận CP-S16-A |

## Giả định cần đối chiếu khi ghép

1. **Thay `device_stub` bằng model `Device` thật của TV2 (giữ cột `id`, `state`):**
   - Hiện tại TV3 dùng bảng giả lập `DeviceStub` (`backend/app/models/device_stub.py`) với các cột `id`, `device_code`, `name`, `state` (`Registered`, `Provisioned`, `Active`, `Offline`, `Fault`, `Maintenance`, `Decommissioned`). Khi ghép với nhánh của TV2, chỉ cần đổi import trong `backend/app/security/device_guard.py` sang model `Device` chính thức của TV2.
2. **Gắn `require_role` và `require_device_access` vào endpoint thật, bỏ `fake_devices.py`:**
   - Gỡ bỏ router giả lập `backend/app/routers/fake_devices.py` khỏi `backend/app/main.py` và gắn `Depends(require_role(...))` + `Depends(require_device_access)` vào các router thiết bị, telemetry, lệnh điều khiển và cảnh báo thật của TV2.
3. **Gọi `audit.log` ở thao tác của TV2 (lệnh bơm, cấu hình, provision):**
   - Trong các endpoint của TV2 (`POST /api/devices/{id}/commands`, `PUT /api/devices/{id}/config`, `POST /api/devices/{id}/provision`, đổi trạng thái thiết bị), gọi `audit.log(db, user=current_user, action=..., target_type="device", target_id=str(device_id), ip=..., detail=...)`.
4. **Gọi `broker_admin` trong luồng provision và đổi trạng thái của TV2:**
   - Khi `Provisioned`: gọi `broker_admin.generate_device_password()` + `broker_admin.create_client(device_code, password)` (hiển thị mật khẩu đúng 1 lần cho Admin, lưu bản băm vào DB).
   - Khi chuyển sang `Maintenance`: gọi `broker_admin.disable_client(device_code)`; khi quay lại `Active`: gọi `broker_admin.enable_client(device_code)`.
   - Khi chuyển sang `Decommissioned`: gọi `broker_admin.delete_client(device_code)` để thu hồi vĩnh viễn trên Mosquitto.
5. **Cho ingest của TV2 gọi `is_device_active` và các bộ giới hạn payload/tần suất:**
   - Trong MQTT subscriber của TV2, gọi `inspect_incoming_message(device_id, raw_payload)` và `validate_telemetry_payload(payload_dict)` từ `backend/app/security/device_guard.py` trước khi lưu bản tin vào bảng `telemetry`.
6. **Chạy lại F1, S1–S6 trên hệ thống đã ghép; bổ sung F8 với thiết bị thật; diễn tập bước demo 1, 9, 10:**
   - Chạy lại toàn bộ script trong `tests/security/` trên hệ thống đã tích hợp 4 thành viên; thử kịch bản `F8` với nút ESP32 thật của TV1; diễn tập kịch bản demo nhóm (Bước 1: Đăng nhập & phân quyền, Bước 9: Kiểm thử bảo mật S1/S2/S6, Bước 10: Thu hồi thiết bị F8/S3).

## Việc còn tồn đọng
- Hoàn tất CP-S16-A: Người dùng đẩy nhánh lên GitHub, mở Pull Request sử dụng nội dung trong `docs/pr-description-tv3.md`, xin review từ TV2 & TV4, chạy `gitleaks` và gắn tag `v1.0.0` khi đóng băng code.
