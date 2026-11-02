# Sơ đồ Kiến trúc, Phân quyền và Mô hình Mối đe dọa – TV3

Thư mục này chứa 4 sơ đồ Mermaid (`.mmd`) phục vụ các mục 12, 13, 14 của báo cáo đồ án:

1. [`deployment-architecture.mmd`](file:///d:/WMS_TV3_Local/docs/diagrams/deployment-architecture.mmd): Sơ đồ triển khai 4 container (`wms-mosquitto`, `wms-mysql`, `wms-backend`, `wms-frontend`), mạng nội bộ `wms_net`, cổng và Docker volumes.
2. [`rbac-matrix.mmd`](file:///d:/WMS_TV3_Local/docs/diagrams/rbac-matrix.mmd): Sơ đồ phân quyền RBAC 3 vai trò (`Admin`, `Operator`, `Viewer`) và phạm vi thiết bị (`user_devices`).
3. [`threat-model.mmd`](file:///d:/WMS_TV3_Local/docs/diagrams/threat-model.mmd): Mô hình mối đe dọa ánh xạ sang biện pháp phòng vệ và mã kiểm thử (`F1`, `S1`–`S6`, `F8`, `S13`).
4. [`sequence-auth-jwt.mmd`](file:///d:/WMS_TV3_Local/docs/diagrams/sequence-auth-jwt.mmd): Biểu đồ trình tự (Sequence Diagram) luồng đăng nhập cấp phát JWT và gọi API điều khiển thiết bị có kiểm tra RBAC + phạm vi thiết bị + Audit Log.

---

## 1. Bảng Ma trận Vai trò – Quyền (Sinh từ `PERMISSION_MATRIX` trong `backend/app/security/rbac.py`)

| Mã quyền / Hành động | Mô tả | `Admin` | `Operator` | `Viewer` |
| --- | --- | :---: | :---: | :---: |
| `users:manage` | Tạo, sửa, khóa/mở khóa tài khoản, đổi vai trò, gán thiết bị (`/api/users`) | ✅ Toàn quyền | ❌ (`403`) | ❌ (`403`) |
| `devices:provision` | Đăng ký thiết bị mới và sinh thông tin kết nối MQTT | ✅ Toàn quyền | ❌ (`403`) | ❌ (`403`) |
| `devices:state` | Đổi trạng thái vòng đời thiết bị (`Active`, `Maintenance`, `Decommissioned`...) | ✅ Toàn quyền | ❌ (`403`) | ❌ (`403`) |
| `audit_logs:read` | Xem và lọc nhật ký kiểm toán hệ thống (`/api/audit-logs`) | ✅ Toàn quyền | ❌ (`403`) | ❌ (`403`) |
| `devices:read` | Xem danh sách và chi tiết thiết bị | ✅ Mọi thiết bị | ✅ Chỉ thiết bị được gán (`user_devices`) | ✅ Mọi thiết bị (chỉ đọc) |
| `telemetry:read` | Xem dữ liệu cảm biến và lịch sử mực nước/lưu lượng | ✅ Mọi thiết bị | ✅ Chỉ thiết bị được gán (`user_devices`) | ✅ Mọi thiết bị (chỉ đọc) |
| `commands:create` | Gửi lệnh bật/tắt bơm từ xa (`/api/devices/{id}/commands`) | ✅ Mọi thiết bị | ✅ Chỉ thiết bị được gán (`user_devices`) | ❌ (`403`) |
| `devices:config` | Cập nhật ngưỡng mực nước và cấu hình thiết bị | ✅ Mọi thiết bị | ✅ Chỉ thiết bị được gán (`user_devices`) | ❌ (`403`) |
| `alerts:read` | Xem danh sách cảnh báo | ✅ Mọi thiết bị | ✅ Chỉ thiết bị được gán (`user_devices`) | ✅ Mọi thiết bị (chỉ đọc) |
| `alerts:ack` | Xác nhận (`acknowledge`) cảnh báo đang hoạt động | ✅ Mọi thiết bị | ✅ Chỉ thiết bị được gán (`user_devices`) | ❌ (`403`) |

---

## 2. Bảng Mô hình Mối đe dọa (Threat Model → Biện pháp → Mã kiểm thử)

| Mã | Mối đe dọa (Threat) | Biện pháp phòng vệ trong hệ thống (Mitigation) | Mã kiểm thử & Bằng chứng |
| --- | --- | --- | --- |
| **T1** | Người dùng vượt quyền vai trò hoặc `Operator` điều khiển trái phép thiết bị thuộc khu vực của người khác | Kiểm tra vai trò bằng `require_role(...)` kết hợp kiểm tra bảng `user_devices` bằng `require_device_access(...)`; ghi nhật ký `rbac.role_denied` / `rbac.device_access_denied` | **F1**, **S1** (`docs/evidence/f1-rbac-matrix.txt`, `docs/evidence/s1-cross-device.txt`) |
| **T2** | Truy cập API không có token, sửa nội dung JWT hoặc dùng lại token đã hết hạn / đã đăng xuất | Xác thực Bearer JWT chuẩn `HS256` (`exp`, `iat`, `jti`), danh sách thu hồi `jti` khi logout, khóa tài khoản tức thời (`is_active`), WebSocket yêu cầu bản tin auth trong 5 giây | **S2** (`docs/evidence/s2-401.txt`) |
| **T3** | Thiết bị phần cứng bị đánh cắp, hỏng hoặc đã ngừng sử dụng (`Decommissioned`) nhưng vẫn gửi dữ liệu giả mạo | Cơ chế thu hồi 2 lớp: (1) Xóa/khóa tài khoản MQTT tức thời qua Mosquitto Dynamic Security (`broker_admin.py`); (2) Backend kiểm tra `is_device_active(device_id)` trước khi xử lý | **S3 / F8** (`docs/evidence/s3-broker-revoke.txt`, `docs/evidence/s3-f8-full-revoke.txt`) |
| **T4** | Thiết bị IoT A bị chiếm quyền cố tình publish vào topic của thiết bị B hoặc gửi lệnh giả mạo lên topic `cmd` | Phân tách tài khoản MQTT cho từng thiết bị kèm ACL / Dynamic Security Role riêng: chỉ được publish `wms/<device_id>/telemetry\|status\|ack` và subscribe `wms/<device_id>/cmd\|config` | **S4** (`docs/evidence/s4-acl-log.txt`) |
| **T5** | Thiết bị hoặc kẻ tấn công bơm payload quá lớn (> 2 KB), tần suất cao (DoS) hoặc dữ liệu sai miền giá trị / chứa mã độc SQLi, XSS | Bộ lọc `device_guard.py`: chặn bản tin > 2048 bytes, giới hạn tối đa 12 bản tin/phút/thiết bị, kiểm tra cấu trúc và miền giá trị vật lý bằng `validate_telemetry_payload()` | **S5** (`docs/evidence/s5-payload-validation.txt`) |
| **T6** | Tấn công dò mật khẩu liên tục (Brute-force) vào API đăng nhập `/api/auth/login` | Mật khẩu băm bằng `bcrypt` (có salt ngẫu nhiên); khóa tạm tài khoản 15 phút sau 5 lần nhập sai liên tiếp (`failed_attempts`, `locked_until`); giới hạn tần suất theo IP | **S6** (`docs/evidence/s6-lockout.txt`) |
| **T7** | Nghe lén (Sniffing) thông tin xác thực và dữ liệu điều khiển trên đường truyền mạng | Bật TLS 1.2/1.3 trên cổng `8883` cho Mosquitto và HTTPS trên cổng `8443` cho Nginx sử dụng chứng thư số ký bởi CA nội bộ (`deployment/certs/ca.crt`) | **S13** (`docs/evidence/s-tls-wireshark.png`, `docs/evidence/s13-tls-cli.txt`) |

---

## 3. Hướng dẫn xuất ảnh PNG/SVG (Dành cho CP-S15-A)

Bạn có thể xuất 4 file `.mmd` sang ảnh `.png` hoặc `.svg` bằng một trong hai cách:
- **Cách 1 (Trực tuyến):** Mở [https://mermaid.live](https://mermaid.live), dán nội dung từng file `.mmd` vào khung Code và bấm **Actions -> PNG / SVG**, lưu vào `docs/diagrams/` với tên tương ứng (`deployment-architecture.png`/`.svg`, `rbac-matrix.png`/`.svg`, `threat-model.png`/`.svg`, `sequence-auth-jwt.png`/`.svg`).
- **Cách 2 (Vẽ lại hoặc chỉnh sửa):** Dùng [draw.io](https://app.diagrams.net/) (`Arrange -> Insert -> Advanced -> Mermaid`) để nhập mã Mermaid, tinh chỉnh bố cục theo ý thích và xuất ra PNG/SVG lưu vào `docs/diagrams/`.
