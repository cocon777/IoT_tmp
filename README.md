# Hệ thống quản lý cấp nước thông minh (Smart Water Management System – WMS)

Đồ án học phần **IoT và Ứng dụng** – Nhóm 4 sinh viên.  
Nhánh/Phân hệ hiện tại: **Thành viên 3 (TV3) – Bảo mật, Phân quyền và Triển khai (`Nguyễn Văn Quang – B23DCCN690`)**.

---

## 1. Cấu trúc thư mục dự án

```text
wms-iot-project/
├── firmware/               # Mã nguồn cho node ESP32 (TV1)
├── hardware/               # Sơ đồ đấu nối và danh mục linh kiện (TV1)
├── backend/                # Dịch vụ FastAPI + SQLAlchemy + PyJWT + paho-mqtt (TV2, TV3)
│   └── app/
│       ├── models/         # ORM: User, UserDevice, AuditLog (TV3) & DeviceStub (chờ ghép TV2)
│       ├── routers/        # API: /api/auth, /api/users, /api/audit-logs, /ws, stub /api/devices
│       ├── security/       # Xác thực JWT/bcrypt, Lockout, RBAC, Device Guard (TV3)
│       └── services/       # Audit Log có che bí mật, Mosquitto Dynamic Security Admin (TV3)
├── database/               # Schema, migration và script nạp dữ liệu mẫu seed_dev.py (TV2, TV3)
├── frontend/               # Giao diện Web Dashboard (TV4)
├── deployment/             # Docker Compose 4 container, Mosquitto, Nginx, Certs, Scripts (TV3)
├── tests/                  # Bộ kiểm thử pytest và kịch bản bảo mật F1, S1–S6, F8 (TV3)
└── docs/                   # Sơ đồ Mermaid (diagrams/), bằng chứng (evidence/), ghi chú tích hợp
```

---

## 2. Yêu cầu công cụ cài đặt trước

- **Docker Engine** & **Docker Compose v2+** (`docker compose version`)
- **Git** và **Git Bash** (trên Windows) hoặc shell tương đương trên Linux/macOS
- **OpenSSL** (`openssl version`) để sinh khóa bí mật và chứng thư TLS nội bộ
- **Mosquitto Clients** (`mosquitto_pub`, `mosquitto_sub`) và **curl** để chạy script kiểm thử

---

## 3. Hướng dẫn cài đặt và khởi chạy từ máy sạch (Phân hệ TV3)

### Bước 1: Sao chép kho mã nguồn và tạo file biến môi trường `.env`

Bạn có thể tự sao chép `.env.example` sang `.env` hoặc chạy script tự động sinh mật khẩu ngẫu nhiên:

```bash
# Cách 1 (Khuyên dùng): Tự động sinh .env với khóa ngẫu nhiên từ .env.example
bash deployment/scripts/make_env.sh

# Cách 2: Sao chép thủ công rồi tự điền các giá trị change_me_*
cp .env.example .env
```

### Bước 2: Sinh chứng thư số TLS nội bộ (CA & Server Certificate)

Script dưới đây sinh `ca.key`, `ca.crt`, `server.key`, `server.crt` (có `subjectAltName` cho `localhost`, `mosquitto`, `127.0.0.1`) phục vụ MQTT TLS (`8883`) và HTTPS Nginx (`8443`):

```bash
bash deployment/certs/gen_certs.sh
```

*(Lưu ý: Chỉ `deployment/certs/ca.crt` được đưa vào Git để TV1 nạp vào ESP32; các khóa `.key` đã được chặn bởi `.gitignore`).*

### Bước 3: Khởi tạo file mật khẩu Mosquitto ban đầu

```bash
bash deployment/scripts/init_mosquitto_passwd.sh
```

### Bước 4: Khởi chạy 4 container bằng Docker Compose

```bash
docker compose --env-file .env -f deployment/docker-compose.yml up -d --build
```

Kiểm tra trạng thái 4 container (`wms-mosquitto`, `wms-mysql`, `wms-backend`, `wms-frontend`):

```bash
docker compose -f deployment/docker-compose.yml ps
curl -i http://localhost:8000/health
```

### Bước 5: (Tùy chọn) Khởi tạo Mosquitto Dynamic Security và nạp dữ liệu mẫu

```bash
# Khởi tạo cấu hình Dynamic Security (quản trị tài khoản MQTT động ở runtime)
bash deployment/scripts/init_mosquitto_dynsec.sh

# Nạp tài khoản người dùng mẫu, thiết bị mẫu và gán quyền Operator vào MySQL
docker exec wms-backend python /database/seed_dev.py
```

---

## 4. Cổng dịch vụ và Tài khoản mẫu (Môi trường Phát triển)

### 4.1. Các cổng dịch vụ

| Dịch vụ | Container | Cổng mở ra Host | Ghi chú |
| --- | --- | --- | --- |
| **FastAPI Backend** | `wms-backend` | `http://localhost:8000` (`/docs`, `/health`, `/ws`) | Chạy `--workers 1` |
| **Nginx Frontend** | `wms-frontend` | `http://localhost:8080` & `https://localhost:8443` | HTTP & HTTPS (TLS) |
| **Mosquitto Broker** | `wms-mosquitto` | `localhost:1883` (Dev) & `localhost:8883` (TLS) | `allow_anonymous false` |
| **MySQL 8.0** | `wms-mysql` | *Không mở ra Host* (chỉ nội bộ `mysql:3306` trên `wms_net`) | Đảm bảo an toàn CSDL |

### 4.2. Tài khoản người dùng Web/API mẫu (tạo bởi `database/seed_dev.py`)

| Vai trò (`role`) | Email đăng nhập | Mật khẩu mẫu | Phạm vi thiết bị (`user_devices`) |
| --- | --- | --- | --- |
| **`Admin`** | `admin@wms.io` | `Admin@123` | Toàn bộ thiết bị (`wms-001`, `wms-002`, ...) |
| **`Operator`** | `op1@wms.io` | `Operator@123` | Chỉ được gán thiết bị số `1` (`wms-001`) |
| **`Operator`** | `op2@wms.io` | `Operator@123` | Chỉ được gán thiết bị số `2` (`wms-002`) |
| **`Viewer`** | `viewer@wms.io` | `Viewer@123` | Xem toàn bộ thiết bị (chỉ đọc, không điều khiển) |

### 4.3. Tài khoản MQTT mẫu (cho thiết bị ESP32 và Backend)

| Username MQTT | Mật khẩu mặc định (Dev) | Quyền ACL trên Topic |
| --- | --- | --- |
| `backend` | Theo `MOSQUITTO_BACKEND_PASSWORD` trong `.env` | Đọc/ghi `wms/#` |
| `dynsec_admin` | Theo `MOSQUITTO_ADMIN_PASSWORD` trong `.env` | Quản trị `$CONTROL/dynamic-security/#` |
| `wms-001` | `wms-001-secret` | Publish `wms/wms-001/telemetry\|status\|ack`, Subscribe `wms/wms-001/cmd\|config` |
| `wms-002` | `wms-002-secret` | Publish `wms/wms-002/telemetry\|status\|ack`, Subscribe `wms/wms-002/cmd\|config` |

---

## 5. Chạy bộ kiểm thử tự động và kịch bản bảo mật (F1, S1–S6, F8)

```bash
# 1. Chạy toàn bộ bộ kiểm thử pytest (34 test cases cho S4 -> S14)
docker exec wms-backend pytest -v /app/tests

# 2. Chạy các kịch bản xuất bằng chứng vào docs/evidence/
docker exec wms-backend python /app/tests/security/s14_f1_rbac_matrix.py
docker exec wms-backend python /app/tests/security/s07_s1_evidence.py
bash tests/security/s05_jwt_401.sh
docker exec wms-backend python /app/tests/security/s14_s3_f8_revoke_full.py
bash tests/security/s03_broker_acl.sh
docker exec wms-backend python /app/tests/security/s14_s5_malicious_payloads.py
docker exec wms-backend python /app/tests/security/s06_lockout_evidence.py
bash tests/security/s13_tls_verify.sh
```

---

## 6. Công cụ AI đã dùng (Khai báo minh bạch)

Trong quá trình thực hiện phân hệ **TV3 (Bảo mật và triển khai)**, thành viên TV3 có sử dụng công cụ trợ lý lập trình AI với phạm vi cụ thể như sau:

- **Công cụ sử dụng:** **Google Antigravity** (Agentic AI Coding Assistant).
- **Phạm vi hỗ trợ:**
  1. Hỗ trợ dựng khung cấu hình `deployment/docker-compose.yml`, script sinh biến môi trường `make_env.sh`, script sinh chứng thư số nội bộ `gen_certs.sh` và cấu hình Mosquitto ACL / Dynamic Security / TLS.
  2. Hỗ trợ viết mã nguồn các mô-đun bảo mật của TV3 theo thiết kế đã thống nhất của nhóm: xác thực JWT & băm mật khẩu `bcrypt` (`security/auth.py`), khóa tạm tài khoản & giới hạn tần suất (`security/lockout.py`), phân quyền RBAC & phạm vi thiết bị (`security/rbac.py`), kiểm tra payload & trạng thái thiết bị (`security/device_guard.py`), nhật ký kiểm toán tự động che bí mật (`services/audit.py`), và quản trị tài khoản MQTT động (`services/broker_admin.py`).
  3. Hỗ trợ sinh các kịch bản kiểm thử tự động (`pytest` và `tests/security/*`) cho các mã kiểm thử `F1`, `S1`–`S6`, `F8` và mã nguồn sơ đồ Mermaid trong `docs/diagrams/`.
- **Phần do sinh viên (TV3) trực tiếp thực hiện, kiểm chứng và chịu trách nhiệm:**
  1. Thiết lập kho mã nguồn GitHub, cấu hình bảo vệ nhánh (`branch protection`), quản lý biến môi trường và khóa bí mật cục bộ.
  2. Trực tiếp đọc hiểu, rà soát từng mô-đun qua 5 cổng kiểm duyệt mã nguồn (`Review Gate` tại các bước S5, S6, S7, S11, S13), đối chiếu với yêu cầu kỹ thuật của đồ án.
  3. Trực tiếp bắt gói tin và phân tích lưu lượng mã hóa MQTT over TLS (`8883`) bằng **Wireshark** (`docs/evidence/s-tls-wireshark.png`), chuyển giao chứng thư CA cho TV1 (ESP32) và viết nội dung báo cáo bằng lời văn của mình.
