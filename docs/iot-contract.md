# HỢP ĐỒNG GIAO TIẾP MQTT IOT (INTERFACE CONTRACT)
> **Dự án:** Hệ thống Quản lý Nước Thông minh (Smart Water Management System - WMS)  
> **Phiên bản:** 1.0  
> **Phạm vi:** Giao tiếp giữa Firmware thiết bị (ESP32 / Vi điều khiển - TV1) và Máy chủ Backend (TV2 + TV3).

---

## 1. THÔNG SỐ KẾT NỐI MẠNG & BROKER MQTT

* **Giao thức:** MQTT v3.1.1 hoặc v5.0 qua TLS (Mã hóa đường truyền).
* **Broker Host / IP:** `<IP_HOAC_DOMAIN_MAY_CHU>` (Ví dụ: `192.168.100.95` trong mạng nội bộ).
* **Port TLS (Khuyên dùng):** `8883` (Yêu cầu nạp `ca.crt` - xem chi tiết tại `docs/notes/tls-for-esp32.md`).
* **Port thường (Dev/Test):** `1883` (TCP không mã hóa).
* **Client ID:** Đặt theo mã thiết bị (Ví dụ: `wms-001`, `wms-002`).
* **Username:** Chính là mã thiết bị (Ví dụ: `wms-001`).
* **Password:** Mã bí mật (Secret key) do Backend cấp một lần duy nhất khi Provisioning thiết bị trên Web.
* **Keep Alive:** Khuyên dùng `30` giây hoặc `60` giây.

---

## 2. DANH SÁCH CÁC TOPIC MQTT

Giả sử mã thiết bị định danh là `{device_code}` (Ví dụ: `wms-001`):

| STT | Chiều dữ liệu | Tên Topic | QoS | Retain | Mục đích |
|:---:|:---|:---|:---:|:---:|:---|
| 1 | **Device ➔ Server** | `wms/{device_code}/telemetry` | 1 | False | Gửi dữ liệu cảm biến đo mực nước, lưu lượng định kỳ |
| 2 | **Device ➔ Server** | `wms/{device_code}/status` | 1 | False | Báo trạng thái Online / Offline (gửi qua LWT) |
| 3 | **Server ➔ Device** | `wms/{device_code}/cmd` | 1 | False | Nhận lệnh điều khiển bơm từ Web |
| 4 | **Device ➔ Server** | `wms/{device_code}/ack` | 1 | False | Báo cho Server biết đã nhận & xử lý lệnh bơm xong |
| 5 | **Server ➔ Device** | `wms/{device_code}/config` | 1 | True | Nhận cấu hình ngưỡng vận hành từ Server |

---

## 3. ĐỊNH DẠNG DỮ LIỆU CHI TIẾT (PAYLOAD JSON)

### 3.1. Dữ liệu cảm biến định kỳ: `wms/{device_code}/telemetry`
Thiết bị gửi định kỳ theo chu kỳ `sample_interval_s` (mặc định 5s - 10s).

```json
{
  "device_id": "wms-001",
  "boot_id": "b-01",
  "seq": 105,
  "ts": "2026-11-02T12:00:00Z",
  "distance_cm": 15.5,
  "level_pct": 38.0,
  "flow_lpm": 2.5,
  "flow_total_l": 12.0,
  "pump_on": 1,
  "fault": "",
  "rssi": -65
}
```

#### Quy tắc kiểm tra (Validation Rules phía Server):
* `device_id` *(chuỗi, bắt buộc)*: Phải khớp 100% với `{device_code}` trên topic.
* `boot_id` *(chuỗi, max 16 ký tự)*: Mã phiên khởi động của ESP32 (sinh ngẫu nhiên khi bật nguồn, ví dụ `b-01`).
* `seq` *(số nguyên `>= 0`)*: Số thứ tự gói tin tự tăng. Cặp `(device_id, boot_id, seq)` là duy nhất; gói trùng sẽ bị bỏ qua.
* `ts` *(chuỗi ISO-8601 UTC, bắt buộc đuôi `Z`)*: Thời điểm đo thực tế sau khi đã đồng bộ NTP (Ví dụ: `2026-11-02T12:00:00Z`). Dung sai tối đa: ±60 giây so với giờ server.
* `distance_cm` *(số thực)*: Khoảng cách cảm biến siêu âm đo được tới mặt nước (`0.0` đến `1000.0` cm).
* `level_pct` *(số thực, bắt buộc)*: Phần trăm mực nước trong bồn (`0.0` đến `100.0`).
* `flow_lpm` *(số thực)*: Lưu lượng nước tức thời (`>= 0.0` Lít/phút).
* `flow_total_l` *(số thực)*: Tổng lưu lượng nước tích lũy (`>= 0.0` Lít).
* `pump_on` *(số nguyên `0`/`1` hoặc boolean)*: `1` nếu rơ-le bơm đang đóng, `0` nếu rơ-le bơm đang ngắt.
* `fault` *(chuỗi)*: Để rỗng `""` nếu bình thường; điền mã lỗi nếu hỏng phần cứng (Ví dụ: `"SENSOR_ERROR"`).
* `rssi` *(số nguyên âm)*: Cường độ sóng Wi-Fi (`-120` đến `0` dBm).

---

### 3.2. Trạng thái kết nối & Heartbeat: `wms/{device_code}/status`

#### a. Khi thiết bị khởi động và kết nối thành công:
Thiết bị bắn bản tin:
```json
{
  "status": "online",
  "fw_version": "1.0.0",
  "config_version": 1,
  "free_heap": 182400
}
```
* `status`: Bắt buộc là `"online"`.
* `fw_version` *(tùy chọn)*: Phiên bản firmware hiện tại.
* `config_version` *(tùy chọn)*: Phiên bản cấu hình đang lưu trong Flash.
* `free_heap` *(tùy chọn)*: Dung lượng RAM còn trống của ESP32 (byte).

#### b. Cấu hình Last Will and Testament (LWT):
Khi gọi lệnh `connect()` trên thư viện MQTT của ESP32, **bắt buộc đăng ký LWT**:
* **Topic LWT:** `wms/{device_code}/status`
* **Message LWT:** `{"status": "offline"}`
* **QoS LWT:** 1
* **Retain LWT:** False
> *Ý nghĩa:* Khi ESP32 mất nguồn hoặc mất Wi-Fi đột ngột, Broker sẽ tự gửi gói này để Server đánh dấu thiết bị `Offline` và phát cảnh báo.

---

### 3.3. Nhận lệnh điều khiển bơm từ Server: `wms/{device_code}/cmd`
Thiết bị cần `subscribe` topic này ngay sau khi kết nối.

Server gửi xuống lệnh bật/tắt bơm có cấu trúc:
```json
{
  "cmd_id": "8e37e9d7-8db1-4c17-9109-1a52fa3169dc",
  "action": "pump",
  "value": "on",
  "duration_s": 60
}
```
* `cmd_id` *(chuỗi UUID)*: Mã định danh lệnh duy nhất.
* `action`: `"pump"` (điều khiển máy bơm).
* `value`: 
  * `"on"`: Bật rơ-le máy bơm. Thiết bị kích hoạt timer đếm ngược tối đa `duration_s` (giây) rồi **tự động ngắt** để chống tràn an toàn.
  * `"off"`: Ngắt rơ-le máy bơm ngay lập tức.
* `duration_s`: Thời gian chạy tối đa (giây). Chỉ có khi `value == "on"`.

---

### 3.4. Xác nhận phản hồi lệnh (ACK): `wms/{device_code}/ack`
Ngay sau khi nhận lệnh từ topic `cmd` và điều khiển chân GPIO rơ-le, thiết bị **bắt buộc gửi ngay bản tin ACK** về Server:

```json
{
  "cmd_id": "8e37e9d7-8db1-4c17-9109-1a52fa3169dc",
  "result": "ok",
  "error": "",
  "ts": "2026-11-02T12:00:05Z"
}
```
* `cmd_id`: Sao chép chính xác `cmd_id` từ lệnh nhận được.
* `result`: `"ok"` (thành công) hoặc `"error"` (thất bại).
* `error`: Để rỗng `""` nếu thành công; ghi nguyên nhân nếu thất bại (Ví dụ: `"HARDWARE_RELAY_FAULT"`).
* `ts`: Thời điểm thực thi lệnh (ISO-8601 UTC).

> ⚠️ **LƯU Ý:** Nếu Server không nhận được gói ACK này trong vòng `10 giây`, Server sẽ đánh dấu lệnh bị `timeout` và báo lỗi trên Web.

---

### 3.5. Nhận cập nhật cấu hình vận hành: `wms/{device_code}/config`
Server lưu cấu hình mới nhất dạng **Retained** trên topic này. Khi khởi động hoặc khi Admin đổi ngưỡng trên Web, Server sẽ gửi:

```json
{
  "version": 2,
  "config": {
    "sample_interval_s": 5,
    "tank_height_cm": 25.0,
    "low_pct": 20.0,
    "high_pct": 90.0,
    "pump_max_run_s": 120,
    "auto_mode": true,
    "dry_run_s": 10
  }
}
```

#### Ý nghĩa các tham số cấu hình:
1. `sample_interval_s` *(1 - 300s)*: Chu kỳ gửi gói tin `telemetry`.
2. `tank_height_cm` *(5 - 500cm)*: Chiều cao tối đa của bồn nước để tính phần trăm mực nước.
3. `low_pct` *(0 - 100%)*: Ngưỡng nước cạn (mặc định `20%`). Dưới mức này Server sẽ kích hoạt cảnh báo `LOW_LEVEL` và bật bơm nếu `auto_mode = true`.
4. `high_pct` *(0 - 100%)*: Ngưỡng nước đầy (mặc định `90%`). Vượt mức này Server kích hoạt cảnh báo `HIGH_LEVEL` và tự ngắt bơm.
5. `pump_max_run_s` *(5 - 3600s)*: Thời gian chạy bơm liên tục tối đa (mặc định `120s`).
6. `auto_mode` *(boolean)*: `true` cho phép Server tự động ra lệnh bơm khi cạn/đầy.
7. `dry_run_s` *(3 - 120s)*: Thời gian kiểm tra chạy khô (bơm bật nhưng không có lưu lượng nước).

Thiết bị nhận bản tin này ➔ Lưu vào Flash (Preferences/EEPROM/NVS) ➔ Báo `config_version` mới lên topic `status`.
