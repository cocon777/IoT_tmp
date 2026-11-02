# Hướng dẫn kết nối MQTT over TLS (Cổng 8883) cho ESP32 – Gửi TV1

Tài liệu này do **TV3 (Bảo mật và triển khai)** chuẩn bị để **TV1** nạp chứng thư CA vào firmware ESP32 và kết nối tới Mosquitto qua cổng `8883` (TLSv1.2).

---

## 1. Hai yêu cầu bắt buộc trên ESP32 khi dùng TLS
1. **Phải đồng bộ thời gian thực qua NTP (`configTime`) trước khi kết nối TLS:**
   - Khi khởi động, đồng hồ của ESP32 mặc định ở năm `1970`. Nếu chưa đồng bộ giờ NTP, `mbedTLS` trên ESP32 sẽ báo lỗi chứng thư chưa có hiệu lực (`certificate is not yet valid`).
2. **Phải nạp chứng thư Root CA công khai (`deployment/certs/ca.crt`) bằng `espClient.setCACert(CA_CERT)`:**
   - **Không** dùng `espClient.setInsecure()` ở bản chính thức vì sẽ mất khả năng chống tấn công Man-in-the-Middle (MitM).
   - Địa chỉ IP hoặc hostname đặt trong `mqttClient.setServer(MQTT_HOST, 8883)` phải khớp với `CN`/`SAN` của chứng thư máy chủ (mặc định đã bao gồm: `192.168.100.95`, `10.22.0.185`, `127.0.0.1`, `localhost`, `mosquitto`). Nếu đổi sang mạng Wi-Fi có IP máy chủ khác, báo TV3 chạy:
     ```bash
     MQTT_TLS_CN=<IP_MAY_CHU_MOI> bash deployment/certs/gen_certs.sh --force
     ```

---

## 2. Chứng thư Root CA công khai (`ca.crt`) để nhúng vào Firmware

```cpp
// File: ca_cert.h (hoặc đặt trực tiếp trong firmware/main.ino)
static const char CA_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIID0zCCArugAwIBAgIUZ/lbk97iWuVXQPpH0I14OYJZio8wDQYJKoZIhvcNAQEL
BQAwcTELMAkGA1UEBhMCVk4xDjAMBgNVBAgMBUhhTm9pMQ4wDAYDVQQHDAVIYU5v
aTEWMBQGA1UECgwNV01TLUlvVC1Hcm91cDEUMBIGA1UECwwLVFYzLVJvb3QtQ0Ex
FDASBgNVBAMMC1dNUy1Sb290LUNBMB4XDTI2MTAyNzA5NTEzNVoXDTM2MTAyNDA5
NTEzNVowcTELMAkGA1UEBhMCVk4xDjAMBgNVBAgMBUhhTm9pMQ4wDAYDVQQHDAVI
YU5vaTEWMBQGA1UECgwNV01TLUlvVC1Hcm91cDEUMBIGA1UECwwLVFYzLVJvb3Qt
Q0ExFDASBgNVBAMMC1dNUy1Sb290LUNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAl6C5HCZXwsx6B52vpMuFDX0wiaH2YEiFBryT9Ua43ldopOWXEXo6
58i/lpb+D0RNAGX0cZUin5P9ZildtiG2D75p2E8aR0S8wwetqP6tQujKfsy8OJXB
f5pTsatJhA71XXNc03fIQK8uKNUypSauye3EESFVK8ngOHxbpBmJEPg1T58PfBAX
cvtCMSDDWMi+FeTydgwfN89wG2EgWw4kLIKkZ4NVXNDQOmsxNPCR1JQ97jH9Fz8e
bF/vp7nlsJJCGluCT4jqKbdDMrig17dQsWJUIdBRDojCASgGbb44ERYYtY87BMFh
+I6jNaL8Fm4iFSm1a28v33bz+mGK+i3X8wIDAQABo2MwYTAdBgNVHQ4EFgQUOfdL
KbKjVrPxhXpgYPR4zMuDC8IwHwYDVR0jBBgwFoAUOfdLKbKjVrPxhXpgYPR4zMuD
C8IwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQEL
BQADggEBAApppHp9R8ztvixWHH7u6QSMc8MFV0ghup1+X9N774epp68XVkufLIZf
4NpF6amVQ18BMjUaBKiSQUmgkeUxj5Pj98WR0RmmtOTlNKYulsobE4tjROrEfGXI
5sqJ1WPwXFExfI0SFNq5ZdIU2vRmTBGyIJHHXPOnzufr9D+TraSH0+yx0uywfFUa
GpgTbFja4iCMIGPR8Hyyurc9dxT+dSB2/TvFX2AVgqANs4JcdIQCN83rSDOnGC88
l1LqjezrQmwledF1VDE0Jdg2cxqI6i0fIwkOUvR3a0pMrZh1vfQiC+crzgfptDyP
KyGQNj3yVdUTWv8RTutPIH9CdIEAGo0=
-----END CERTIFICATE-----
)EOF";
```

---

## 3. Đoạn mã mẫu kết nối `WiFiClientSecure` + `PubSubClient`

```cpp
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>

const char* WIFI_SSID     = "<TEN_WIFI>";
const char* WIFI_PASS     = "<MAT_KHAU_WIFI>";
const char* MQTT_HOST     = "192.168.100.95"; // IP may chu chay Docker Mosquitto
const int   MQTT_TLS_PORT = 8883;
const char* DEVICE_ID     = "wms-001";
const char* DEVICE_PASS   = "<MAT_KHAU_CAP_1_LAN_KHI_PROVISION>";

WiFiClientSecure espTlsClient;
PubSubClient mqttClient(espTlsClient);

void syncNtpTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("[NTP] Waiting for UTC time sync");
  time_t now = time(nullptr);
  while (now < 1700000000) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println("\n[NTP] Time synchronized!");
}

void setupTlsAndMqtt() {
  syncNtpTime();
  espTlsClient.setCACert(CA_CERT);
  mqttClient.setServer(MQTT_HOST, MQTT_TLS_PORT);
  mqttClient.setBufferSize(1024);
}
```
