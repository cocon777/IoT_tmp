#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
CA_FILE="${REPO_ROOT}/deployment/certs/ca.crt"
LOG_FILE="${REPO_ROOT}/docs/evidence/s13-tls-cli.txt"

set -a
# shellcheck disable=SC1090
source <(tr -d '\r' < "${ENV_FILE}")
set +a

TLS_HOST="${MQTT_TLS_TEST_HOST:-127.0.0.2}"
TLS_PORT="${MQTT_TLS_PORT:-8883}"
DEV_USER="${MQTT_SAMPLE_DEVICE_USER:-wms-001}"
DEV_PASS="${MQTT_SAMPLE_DEVICE_PASSWORD}"

mkdir -p "$(dirname "${LOG_FILE}")"
: > "${LOG_FILE}"

log_line() {
    echo "$1" | tee -a "${LOG_FILE}"
}

log_line "=== KIEM THU BAO MAT S13: MQTT OVER TLS (PORT ${TLS_PORT}) ==="
log_line "Target Broker: ${TLS_HOST}:${TLS_PORT}"
log_line "CA Certificate: deployment/certs/ca.crt"
log_line "--------------------------------------------------------"

# 1. Publish voi --cafile ca.crt -> Thanh cong
if mosquitto_pub --cafile "${CA_FILE}" \
    -h "${TLS_HOST}" -p "${TLS_PORT}" \
    -u "${DEV_USER}" -P "${DEV_PASS}" \
    -t "wms/wms-001/telemetry" -q 1 \
    -m '{"device_id":"wms-001","seq":10,"level_pct":78.5,"tls":true}' >/dev/null 2>&1; then
    log_line "[PASS] 1. mosquitto_pub --cafile ca.crt -p ${TLS_PORT} -> THANH CONG"
else
    log_line "[FAIL] 1. mosquitto_pub --cafile ca.crt -p ${TLS_PORT} -> THAT BAI"
    exit 1
fi

# 2. Publish khong co --cafile tren cong 8883 -> That bai
NO_CA_OUT="$(mosquitto_pub \
    -h "${TLS_HOST}" -p "${TLS_PORT}" \
    -u "${DEV_USER}" -P "${DEV_PASS}" \
    -t "wms/wms-001/telemetry" -q 1 \
    -m '{"device_id":"wms-001","seq":11}' 2>&1)"
NO_CA_RC=$?

if [ ${NO_CA_RC} -ne 0 ]; then
    log_line "[PASS] 2. mosquitto_pub KHONG co --cafile tren cong ${TLS_PORT} -> BI TU CHOI (rc=${NO_CA_RC}: ${NO_CA_OUT})"
else
    log_line "[FAIL] 2. mosquitto_pub KHONG co --cafile van thanh cong!"
    exit 1
fi

log_line "--------------------------------------------------------"
log_line "KET QUA TLS CLI: 2/2 PASS"
exit 0
