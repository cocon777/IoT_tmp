# Ghi chú kỹ thuật: Mosquitto Dynamic Security (Bước S11)

## 1. Phiên bản và đường dẫn plugin trong container
- **Image:** `eclipse-mosquitto:2.0`
- **Phiên bản thực tế:** `mosquitto version 2.0.22`
- **Đường dẫn plugin:** `/usr/lib/mosquitto_dynamic_security.so`
- **Cấu hình trong `mosquitto.conf`:**
  ```conf
  plugin /usr/lib/mosquitto_dynamic_security.so
  plugin_opt_config_file /mosquitto/data/dynamic-security.json
  ```
  *(Lưu ý: File `dynamic-security.json` phải đặt trong thư mục có quyền ghi của tiến trình `mosquitto` như `/mosquitto/data/dynamic-security.json` để broker lưu thay đổi tức thời khi nhận lệnh qua `$CONTROL/dynamic-security/v1`).*

## 2. Cách khởi tạo file cấu hình và tách tài khoản quản trị
- Khởi tạo ban đầu bằng `mosquitto_ctrl`:
  ```bash
  mosquitto_ctrl dynsec init /mosquitto/data/dynamic-security.json "${MQTT_DYNSEC_ADMIN_USER}" "${MQTT_DYNSEC_ADMIN_PASSWORD}"
  ```
- **Tách quyền rõ ràng:**
  1. `MQTT_DYNSEC_ADMIN_USER` (`dynsec_admin`): có role `admin` của Dynamic Security, chỉ dùng bởi `services/broker_admin.py` để gửi lệnh JSON tới `$CONTROL/dynamic-security/v1` và nhận phản hồi tại `$CONTROL/dynamic-security/v1/response`.
  2. `MQTT_BACKEND_USER` (`backend`): chỉ có role `backend-role` (đọc/ghi `wms/#`), hoàn toàn không có quyền gọi `$CONTROL/dynamic-security/v1`.
  3. Thiết bị (`wms-001`, `wms-test`, ...): chỉ được phép gửi dữ liệu lên nhánh của chính mình và nhận lệnh/config của chính mình.

## 3. Đặc điểm xử lý `%u` trong ACL của Dynamic Security (Mosquitto 2.0.22)
Qua kiểm tra nhị phân `/usr/lib/mosquitto_dynamic_security.so` trên Mosquitto `2.0.22`:
- Các loại ACL trong Dynamic Security gồm:
  - `publishClientSend`: kiểm tra khi client publish lên broker.
  - `publishClientReceive`: kiểm tra khi broker chuyển bản tin tới client.
  - `subscribeLiteral` / `subscribePattern`: kiểm tra khi client gửi gói `SUBSCRIBE`.
  - `unsubscribeLiteral` / `unsubscribePattern`: kiểm tra khi client gửi gói `UNSUBSCRIBE`.
- **Chi tiết quan trọng về `%u`:**
  - Trong Mosquitto 2.0.22, `subscribePattern` và `unsubscribePattern` hỗ trợ thay thế `%u` (username) và `%c` (clientid).
  - Tuy nhiên, `publishClientSend` và `publishClientReceive` trong `mosquitto_dynamic_security.so` gọi hàm `mosquitto_topic_matches_sub` (không tự thay thế `%u` như `acl_file`).
- **Giải pháp thiết kế trong `broker_admin.py`:**
  - Khai báo role chung `device-base-role` chứa `subscribePattern` / `unsubscribePattern` cho `wms/%u/cmd` và `wms/%u/config`, đồng thời đặt `defaultACLAccess` là `deny` cho cả 4 loại (`publishClientSend`, `publishClientReceive`, `subscribe`, `unsubscribe`).
  - Khi `create_client(username)` được gọi, ngoài việc gán `device-base-role`, hàm tự động tạo kèm role định danh `device-acl-{username}` với các quyền chính xác theo `username`:
    - `publishClientSend`: `wms/{username}/telemetry`, `wms/{username}/status`, `wms/{username}/ack` (`allow`)
    - `publishClientReceive`: `wms/{username}/cmd`, `wms/{username}/config` (`allow`)
    - `subscribeLiteral`: `wms/{username}/cmd`, `wms/{username}/config` (`allow`)
  - Khi `delete_client(username)` được gọi, hàm xóa cả client lẫn role `device-acl-{username}`. Lúc này plugin gọi `mosquitto_kick_client_by_username` ngắt kết nối TCP của thiết bị ngay lập tức mà không cần khởi động lại container.
