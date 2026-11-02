#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
LOG_FILE="${REPO_ROOT}/docs/evidence/s4-acl-log.txt"

if [ ! -f "${ENV_FILE}" ]; then
    echo "ERROR: .env not found" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
source <(tr -d '\r' < "${ENV_FILE}")
set +a

# Neu Windows Mosquitto Service chiem 127.0.0.1:1883, dung 127.0.0.2 de ket noi dung vao Docker 0.0.0.0:1883
BROKER_HOST="${MQTT_TEST_HOST:-127.0.0.2}"
BROKER_PORT="${MQTT_PORT:-1883}"
DEV_USER="${MQTT_SAMPLE_DEVICE_USER:-wms-001}"
DEV_PASS="${MQTT_SAMPLE_DEVICE_PASSWORD}"
BE_USER="${MQTT_BACKEND_USER:-backend}"
BE_PASS="${MQTT_BACKEND_PASSWORD}"

mkdir -p "$(dirname "${LOG_FILE}")"
: > "${LOG_FILE}"

log_line() {
    echo "$1" | tee -a "${LOG_FILE}"
}

PASS_COUNT=0
FAIL_COUNT=0

log_line "=== KIEM THU BAO MAT S3 / S4: MOSQUITTO PASSWORD_FILE & ACL ==="
log_line "Broker: ${BROKER_HOST}:${BROKER_PORT}"
log_line "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log_line "---------------------------------------------------------------"

# Start backend subscriber in background to capture messages on wms/#
BE_SUB_OUT="$(mktemp)"
mosquitto_sub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u "${BE_USER}" -P "${BE_PASS}" \
    -t "wms/#" -v -W 6 > "${BE_SUB_OUT}" 2>&1 &
BE_SUB_PID=$!
sleep 1

# Start unauthorized wms-001 wildcard subscriber on wms/#
DEV_SUB_OUT="$(mktemp)"
mosquitto_sub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u "${DEV_USER}" -P "${DEV_PASS}" \
    -t "wms/#" -v -W 4 > "${DEV_SUB_OUT}" 2>&1 &
DEV_SUB_PID=$!
sleep 1

# 1. wms-001 publish wms/wms-001/telemetry -> thanh cong
PAYLOAD_OK='{"device_id":"wms-001","seq":1,"level_pct":65.0}'
if mosquitto_pub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u "${DEV_USER}" -P "${DEV_PASS}" \
    -t "wms/wms-001/telemetry" -q 1 -m "${PAYLOAD_OK}" >/dev/null 2>&1; then
    log_line "[PASS] 1. wms-001 publish wms/wms-001/telemetry -> thanh cong (QoS 1)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    log_line "[FAIL] 1. wms-001 publish wms/wms-001/telemetry -> that bai"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# 2. wms-001 publish wms/khac/telemetry -> bi tu choi hoac khong phan phoi
PAYLOAD_FORBIDDEN='{"device_id":"khac","seq":99,"level_pct":10.0}'
PUB2_OUT="$(mosquitto_pub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u "${DEV_USER}" -P "${DEV_PASS}" \
    -t "wms/khac/telemetry" -q 1 -m "${PAYLOAD_FORBIDDEN}" 2>&1 || true)"
sleep 1

if ! grep -q "wms/khac/telemetry" "${BE_SUB_OUT}"; then
    log_line "[PASS] 2. wms-001 publish wms/khac/telemetry -> bi chan boi ACL (khong phan phoi toi backend)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    log_line "[FAIL] 2. wms-001 publish wms/khac/telemetry -> van duoc phan phoi!"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

wait "${DEV_SUB_PID}" 2>/dev/null || true
wait "${BE_SUB_PID}" 2>/dev/null || true

# 3. wms-001 subscribe wms/# -> khong nhan duoc gi
if [ ! -s "${DEV_SUB_OUT}" ] || ! grep -q "${PAYLOAD_OK}" "${DEV_SUB_OUT}"; then
    log_line "[PASS] 3. wms-001 subscribe wms/# -> khong nhan duoc ban tin nao (ACL chan doc)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    log_line "[FAIL] 3. wms-001 subscribe wms/# -> nhan duoc ban tin: $(cat "${DEV_SUB_OUT}")"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# 4. Ket noi khong mat khau -> bi tu choi
ANON_OUT="$(mosquitto_pub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -t "wms/wms-001/telemetry" -m "anon" 2>&1)"
ANON_RC=$?
if [ ${ANON_RC} -ne 0 ]; then
    log_line "[PASS] 4. Ket noi khong mat khau (anonymous) -> bi tu choi (rc=${ANON_RC}: ${ANON_OUT})"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    log_line "[FAIL] 4. Ket noi khong mat khau -> van thanh cong!"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# 5. backend subscribe wms/# nhan duoc ban tin o muc 1
if grep -q "wms/wms-001/telemetry ${PAYLOAD_OK}" "${BE_SUB_OUT}"; then
    log_line "[PASS] 5. backend subscribe wms/# -> nhan duoc: $(grep "wms/wms-001/telemetry" "${BE_SUB_OUT}")"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    log_line "[FAIL] 5. backend subscribe wms/# -> khong nhan duoc ban tin muc 1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

rm -f "${BE_SUB_OUT}" "${DEV_SUB_OUT}"

log_line "---------------------------------------------------------------"
log_line "Ket qua: ${PASS_COUNT}/5 PASS, ${FAIL_COUNT}/5 FAIL"

if [ "${FAIL_COUNT}" -ne 0 ]; then
    exit 1
fi
exit 0
