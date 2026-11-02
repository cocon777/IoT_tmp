# Dàn ý và Gợi ý Nội dung Báo cáo – TV3 (Bảo mật & Triển khai)

> **⚠️ LƯU Ý QUAN TRỌNG (Theo Quy tắc Mục 0 & S15 của `AGENT_PLAN_TV3.md`):**
> Tài liệu này là **bản dàn ý và gợi ý kỹ thuật nháp** do Agent tổng hợp từ mã nguồn bạn đã triển khai. Bạn **KHÔNG** nộp nguyên văn file này vào báo cáo nhóm, mà cần đọc hiểu, đối chiếu với code thực tế trong `backend/app/security/`, `backend/app/services/`, `deployment/` và **viết lại bằng văn phong của riêng bạn** vào các mục 12, 13, 14 của báo cáo chung.

---

## Phần A – Dàn ý & Gợi ý Nội dung cho 3 Mục Báo cáo

### 1. Mục 12: Người dùng và phân quyền (User Management & RBAC)

#### 12.1. Dàn ý đề xuất
1. **Mô hình người dùng và bài toán phân quyền trong trạm cấp nước:**
   - Giải thích vì sao hệ thống quản lý cấp nước cần phân tách quyền hạn (tránh thao tác nhầm bật/tắt bơm gây tràn bể hoặc cháy bơm, phân vùng trách nhiệm theo từng trạm/bể chứa).
2. **Thiết kế 3 vai trò (`Admin`, `Operator`, `Viewer`) và Ma trận quyền (`PERMISSION_MATRIX`):**
   - Trình bày 3 vai trò lưu trong cột `role` của bảng `users`:
     - **`Admin` (Quản trị viên):** Quản lý toàn bộ vòng đời người dùng (`/api/users`), cấp phát/thu hồi thiết bị (`devices:provision`, `devices:state`), tra cứu nhật ký kiểm toán (`/api/audit-logs`), và có toàn quyền điều khiển trên mọi thiết bị.
     - **`Operator` (Vận hành viên):** Trực tiếp giám sát, gửi lệnh bật/tắt bơm (`commands:create`), thay đổi ngưỡng mực nước (`devices:config`) và xác nhận cảnh báo (`alerts:ack`), nhưng **chỉ giới hạn trên các thiết bị được Admin gán** trong bảng liên kết nhiều-nhiều `user_devices`.
     - **`Viewer` (Quan sát viên):** Chỉ có quyền đọc (`GET`) danh sách thiết bị, số liệu telemetry và cảnh báo trên toàn hệ thống; mọi thao tác ghi/điều khiển đều bị chặn với mã `403 Forbidden`.
   - Đính kèm **Bảng ma trận quyền** và sơ đồ `rbac-matrix.png` (từ `docs/diagrams/`).
3. **Cơ chế thực thi phân quyền 2 tầng tại Backend & WebSocket:**
   - **Tầng 1 – Kiểm tra vai trò (`require_role`):** Dependency của FastAPI kiểm tra `user.role` trước khi vào hàm xử lý router.
   - **Tầng 2 – Kiểm tra phạm vi thiết bị (`can_access_device` & `require_device_access`):** Khi `Operator` truy cập `/api/devices/{id}/*`, hệ thống truy vấn bảng `user_devices`; nếu không được gán, trả về `403 Forbidden` và ghi nhận sự kiện `rbac.device_access_denied` vào bảng `audit_logs`.
   - **Phân quyền thời gian thực trên WebSocket (`WS /ws`):** Hàm `should_deliver_event(user, device_id)` lọc các sự kiện đẩy xuống trình duyệt, đảm bảo `Operator` chỉ nhận được bản tin của thiết bị mình phụ trách.
4. **An toàn quản trị tài khoản:**
   - Ràng buộc bảo vệ Admin cuối cùng (`_ensure_not_last_active_admin` trong `backend/app/routers/users.py`): Hệ thống từ chối (`400 Bad Request`) nếu quản trị viên cố tự khóa hoặc hạ quyền tài khoản `Admin` đang hoạt động cuối cùng, tránh rủi ro mất quyền quản trị toàn hệ thống.

---

### 2. Mục 13: Bảo mật và quyền riêng tư (Security & Privacy)

#### 13.1. Dàn ý đề xuất
1. **Mô hình mối đe dọa (Threat Model) theo kiến trúc 4 tầng:**
   - Tóm tắt 7 mối đe dọa chính (`T1`–`T7`) từ thiết bị ESP32 → Broker MQTT → Backend API/DB → Giao diện Web (chèn sơ đồ `threat-model.png` và bảng ánh xạ Mối đe dọa → Biện pháp → Mã kiểm thử `S1`–`S6`).
2. **Bảo mật xác thực và chống tấn công dò mật khẩu:**
   - Lưu trữ mật khẩu bằng thuật toán băm thích nghi `bcrypt` kèm salt ngẫu nhiên (`backend/app/security/auth.py`), kiểm tra độ mạnh mật khẩu tối thiểu 8 ký tự gồm chữ hoa, chữ thường và chữ số.
   - Cấp phát JSON Web Token (`PyJWT`, thuật toán `HS256`) có thời hạn (`exp`), mã định danh token (`jti`) và danh sách thu hồi (`blacklist`) khi người dùng đăng xuất hoặc bị khóa tài khoản.
   - Chống vét cạn mật khẩu (`backend/app/security/lockout.py`): Đếm số lần đăng nhập sai liên tiếp (`failed_attempts`); khi đạt ngưỡng **5 lần sai**, tự động khóa tài khoản trong **15 phút** (`locked_until`, trả về `423 Locked`) kết hợp giới hạn tần suất theo địa chỉ IP (tối đa 20 yêu cầu / 5 phút).
3. **Bảo mật tầng giao tiếp IoT (MQTT Broker, Dynamic Security & TLS):**
   - Tắt hoàn toàn kết nối ẩn danh (`allow_anonymous false`).
   - Áp dụng **ACL theo nguyên tắc đặc quyền tối thiểu (Least Privilege)**: Mỗi nút ESP32 (`wms-001`, `wms-002`) có tài khoản riêng, chỉ được `publish` lên `wms/<device_id>/telemetry|status|ack` và chỉ được `subscribe` vào `wms/<device_id>/cmd|config`; tài khoản `backend` mới có quyền trên `wms/#`.
   - Quản trị động bằng plugin **Mosquitto Dynamic Security** (`backend/app/services/broker_admin.py`): Khi thêm hoặc ngừng sử dụng thiết bị (`Decommissioned`), Backend gửi lệnh JSON qua topic `$CONTROL/dynamic-security/v1` để tạo/vô hiệu hóa/xóa client và role tương ứng ngay lập tức mà không cần khởi động lại Broker.
   - Mã hóa đường truyền bằng **TLS 1.2/1.3** trên cổng `8883` (MQTT over TLS) và `8443` (HTTPS Nginx) với chứng thư số ký bởi CA nội bộ (`deployment/certs/ca.crt`), chống nghe lén (minh họa bằng ảnh chụp Wireshark `docs/evidence/s-tls-wireshark.png`).
4. **Bảo vệ luồng thu thập dữ liệu (Device Guard & Kiểm tra Payload):**
   - Cơ chế **thu hồi 2 lớp**: Ngoài việc thu hồi tại Broker, tầng Backend kiểm tra `is_device_active(device_id)` trước khi xử lý bản tin.
   - Giới hạn kích thước bản tin tối đa **2 KB (`2048 bytes`)** và tần suất tối đa **12 bản tin/phút/thiết bị** (`check_payload_size`, `check_device_rate_limit`) để chống làm ngập CSDL.
   - Kiểm tra cấu trúc và miền giá trị vật lý bằng `validate_telemetry_payload`: từ chối bản tin thiếu `ts`, `level_pct` ngoài khoảng `[0, 100]`, lưu lượng/dòng điện âm hoặc chứa chuỗi tấn công SQLi/XSS (`<script>`, `DROP TABLE`).
5. **Nhật ký kiểm toán (Audit Log) và Tự động che thông tin nhạy cảm:**
   - Mọi hành động nhạy cảm (đăng nhập đúng/sai, khóa tài khoản, tạo/sửa user, gán thiết bị, gửi lệnh bơm, đổi cấu hình, từ chối quyền RBAC) đều được ghi vào bảng `audit_logs` kèm `actor_id`, `action`, `target_type`, `target_id`, `detail`, `ip_address` và dấu thời gian.
   - Hàm `_redact_value` trong `backend/app/services/audit.py` tự động quét đệ quy và thay thế các trường chứa từ khóa nhạy cảm (`password`, `secret`, `token`, `mqtt_password`...) bằng `"***REDACTED***"`, đảm bảo bí mật không bao giờ lọt vào nhật ký.
6. **Quyền riêng tư và Bảo vệ dữ liệu cá nhân (Privacy Policy):**
   - **Dữ liệu cá nhân có thu thập:** Hệ thống chỉ thu thập tối thiểu 3 trường phục vụ định danh công việc và truy vết an ninh: `email` công việc, `full_name` (họ tên nhân sự vận hành) trong bảng `users`, và `ip_address` của thiết bị truy cập trong bảng `audit_logs`.
   - **Dữ liệu cam kết KHÔNG thu thập:** Hệ thống chỉ đo đạc thông số kỹ thuật của bể nước (mực nước, lưu lượng, trạng thái bơm); tuyệt đối **không** thu thập vị trí định vị cá nhân (GPS), hình ảnh/camera, âm thanh/microphone hay dữ liệu sức khỏe/sinh trắc học của người dùng.
   - **Chính sách lưu trữ (Data Retention):** Dữ liệu chuỗi thời gian `telemetry` tần suất cao (5 giây/lần) được lưu phục vụ giám sát vận hành và có thể cấu hình dọn dẹp định kỳ (ví dụ giữ chi tiết 30–90 ngày tùy dung lượng máy chủ), trong khi nhật ký kiểm toán `audit_logs` và lịch sử cảnh báo được lưu giữ dài hạn và chỉ `Admin` mới có quyền truy cập.

---

### 3. Mục 14: Triển khai (Deployment & DevSecOps)

#### 14.1. Dàn ý đề xuất
1. **Kiến trúc đóng gói 4 dịch vụ bằng Docker Compose (`deployment/docker-compose.yml`):**
   - Mô tả vai trò và cấu hình của 4 container (chèn sơ đồ `deployment-architecture.png`):
     1. **`wms-mosquitto` (`eclipse-mosquitto:2.0`):** MQTT Broker mở cổng `1883` (chế độ phát triển) và `8883` (TLS), gắn volume `mosquitto_data`, `mosquitto_log` và chứng thư TLS chỉ đọc (`:ro`).
     2. **`wms-mysql` (`mysql:8.0`):** Hệ quản trị CSDL lưu trữ dữ liệu bền vững trên volume `mysql_data`, cấu hình `healthcheck` (`mysqladmin ping`) và **không mở cổng `3306` ra máy chủ host** (chỉ giao tiếp nội bộ trong mạng `wms_net`).
     3. **`wms-backend` (Python 3.11-slim + FastAPI):** Chờ `mysql` đạt trạng thái `service_healthy` mới khởi động; chạy với `--workers 1` để luồng MQTT subscriber và bộ đếm giới hạn tần suất hoạt động đồng nhất trong một tiến trình; mở cổng `8000`.
     4. **`wms-frontend` (`nginx:1.27-alpine`):** Phục vụ giao diện người dùng và reverse proxy trên cổng `8080` (HTTP) và `8443` (HTTPS).
2. **Quản lý cấu hình và bí mật (Secret Management):**
   - Toàn bộ khóa bí mật (`MYSQL_PASSWORD`, `JWT_SECRET`, `MOSQUITTO_BACKEND_PASSWORD`, `MOSQUITTO_ADMIN_PASSWORD`) được sinh ngẫu nhiên bằng `openssl rand -hex` thông qua script `deployment/scripts/make_env.sh` và lưu trong file `.env` (đã chặn trong `.gitignore`).
   - Trên kho mã nguồn Git chỉ lưu trữ `.env.example` (chứa giá trị `change_me_*`) và chứng thư gốc công khai `deployment/certs/ca.crt`; các khóa riêng tư (`*.key`, `server.crt`, `passwd`, `dynamic-security.json`) đều bị loại trừ khỏi Git và được kiểm tra bằng quét bí mật.
3. **Quy trình khởi chạy tự động và kiểm chứng:**
   - Trình bày quy trình 5 bước từ máy sạch đến khi hệ thống sẵn sàng: (1) Chạy `make_env.sh` tạo `.env` → (2) Chạy `gen_certs.sh` sinh CA và chứng thư TLS → (3) Khởi tạo mật khẩu/Dynamic Security cho Mosquitto → (4) `docker compose up -d --build` → (5) Chạy `seed_dev.py` nạp tài khoản mẫu và kiểm tra `/health`, `/docs`.

---

## Phần B – Lý do lựa chọn từng công nghệ (Dùng cho Báo cáo & Bảo vệ)

| Thành phần | Công nghệ lựa chọn | Lý do chọn & So sánh với phương án thay thế |
| --- | --- | --- |
| **Băm mật khẩu** | **`bcrypt`** (thư viện `bcrypt` trực tiếp trên Python) | `bcrypt` là thuật toán băm mật khẩu thích nghi có tích hợp salt ngẫu nhiên 128-bit và hệ số chi phí (`work factor` = 12 rounds), làm chậm đáng kể tấn công vét cạn bằng GPU so với các hàm băm nhanh như `SHA-256`/`MD5`. Việc gọi trực tiếp thư viện `bcrypt` giúp tránh lỗi tương thích giữa `passlib` cũ với `bcrypt >= 4.1` trên Python 3.11+. |
| **Xác thực API & WebSocket** | **JWT (`PyJWT` – `HS256`)** kết hợp danh sách thu hồi `jti` | Phù hợp với kiến trúc REST API + SPA (Frontend tách rời Backend) và dễ dàng truyền trong bản tin đầu tiên của WebSocket. Thêm trường `jti` (JWT ID) kết hợp kiểm tra `user.is_active` trong DB giúp khắc phục nhược điểm kinh điển của JWT thuần túy là không thể thu hồi ngay khi khóa tài khoản. |
| **Quản lý quyền MQTT** | **Mosquitto Dynamic Security Plugin** (`$CONTROL/dynamic-security/v1`) | Với `acl_file` và `password_file` tĩnh truyền thống, mỗi khi Admin đăng ký thêm nút ESP32 mới hoặc thu hồi thiết bị hỏng từ giao diện Web, hệ thống phải sửa file cấu hình và gửi tín hiệu `SIGHUP`/khởi động lại container Mosquitto. Dynamic Security cho phép Backend gửi lệnh JSON qua MQTT để cấp/thu hồi tài khoản và ACL của từng thiết bị theo thời gian thực (`runtime`) mà không làm gián đoạn các thiết bị đang chạy. |
| **Đóng gói & Triển khai** | **Docker Compose** (4 container + mạng cầu nối `wms_net`) | Đảm bảo môi trường chạy đồng nhất 100% giữa 4 thành viên trong nhóm trên Windows/Linux/macOS chỉ với một lệnh `docker compose up`, cô lập được cổng nhạy cảm (`3306` của MySQL chỉ mở trong mạng nội bộ `wms_net`), đồng thời nhẹ và phù hợp quy mô 1 node hơn nhiều so với Kubernetes (K8s). |

---

## Phần C – Bộ Câu hỏi Vấn đáp Tổng hợp để Luyện tập (Kèm Gợi ý Trả lời)

1. **Câu hỏi 1:** *Tại sao hệ thống vừa chặn thiết bị bị thu hồi ở Mosquitto (Dynamic Security) lại vừa phải kiểm tra `is_device_active()` ở Backend?*
   - **Gợi ý trả lời:** Đây là nguyên tắc phòng thủ chiều sâu (Defense-in-Depth). Lớp 1 tại Mosquitto chặn kết nối mạng từ thiết bị bị thu hồi (`Decommissioned`). Tuy nhiên, nếu thiết bị đang giữ kết nối cũ, có bản tin `retained` còn tồn đọng trong hàng đợi, hoặc khi thiết bị chỉ chuyển sang trạng thái bảo trì tạm thời (`Maintenance`), lớp 2 tại Backend (`is_device_active`) vẫn đảm bảo dữ liệu không hợp lệ bị loại bỏ ngay trước khi ghi vào MySQL.

2. **Câu hỏi 2:** *Làm thế nào hệ thống ngăn chặn việc Operator của trạm cấp nước A cố tình đổi ID trên URL (ví dụ `/api/devices/2/commands`) để điều khiển máy bơm của trạm B?*
   - **Gợi ý trả lời:** Đây là lỗ hổng BOLA/IDOR (Broken Object Level Authorization). Để chặn lỗ hổng này, ngoài việc kiểm tra vai trò `Operator` bằng `require_role`, mọi endpoint thao tác trên thiết bị đều gắn thêm dependency `require_device_access`. Hàm này truy vấn bảng `user_devices` xem cặp `(user_id, device_id)` có tồn tại không; nếu không (như kịch bản kiểm thử `S1`), hệ thống trả về `403 Forbidden` và ghi ngay hành vi vi phạm vào bảng `audit_logs`.

3. **Câu hỏi 3:** *Vì sao container `wms-backend` được cấu hình chạy với `--workers 1` và container `wms-mysql` không khai báo `ports: 3306:3306` trong `docker-compose.yml`?*
   - **Gợi ý trả lời:**
     - Với `wms-backend`: Tiến trình Backend vừa phục vụ REST API/WebSocket vừa chạy luồng nền MQTT subscriber lắng nghe `wms/#`. Nếu chạy nhiều worker mà chưa tách MQTT subscriber ra dịch vụ riêng, mỗi worker sẽ cùng subscribe và xử lý trùng lặp mỗi bản tin telemetry nhiều lần.
     - Với `wms-mysql`: Việc không mở cổng `3306` ra máy chủ host giúp cô lập hoàn toàn cơ sở dữ liệu trong mạng nội bộ `wms_net`, chỉ cho phép `wms-backend` kết nối tới, loại bỏ nguy cơ bị quét cổng hoặc tấn công dò mật khẩu MySQL từ mạng bên ngoài.

4. **Câu hỏi 4:** *Nếu Admin lỡ truyền mật khẩu mới khi tạo user hoặc đổi mật khẩu thiết bị, thông tin đó có bị lộ trong bảng `audit_logs` không?*
   - **Gợi ý trả lời:** Không. Trước khi lưu trường `detail` (kiểu JSON) vào bảng `audit_logs`, dịch vụ `audit.log` (`backend/app/services/audit.py`) gọi hàm đệ quy `_redact_value` để kiểm tra tên mọi khóa; bất kỳ khóa nào khớp với danh sách nhạy cảm (`password`, `password_hash`, `secret`, `token`, `mqtt_password`...) đều bị thay thế tự động bằng chuỗi `"***REDACTED***"`.
