#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
PASSWD_FILE="${REPO_ROOT}/deployment/mosquitto/passwd"

if [ ! -f "${ENV_FILE}" ]; then
    bash "${SCRIPT_DIR}/make_env.sh"
fi

if ! grep -q "^MQTT_SAMPLE_DEVICE_PASSWORD=" "${ENV_FILE}"; then
    DEV_PW="$(openssl rand -hex 16)"
    printf "\nMQTT_SAMPLE_DEVICE_USER=wms-001\nMQTT_SAMPLE_DEVICE_PASSWORD=%s\n" "${DEV_PW}" >> "${ENV_FILE}"
fi

# Load variables safely without echoing secrets
set -a
# shellcheck disable=SC1090
source <(tr -d '\r' < "${ENV_FILE}")
set +a

rm -f "${PASSWD_FILE}"
touch "${PASSWD_FILE}"

# Dung mosquitto_passwd cua dung image eclipse-mosquitto:2.0 de tuong thich dinh dang salt
MSYS_NO_PATHCONV=1 docker run --rm -v "${REPO_ROOT}/deployment/mosquitto:/mosquitto/config" eclipse-mosquitto:2.0 \
    sh -c "mosquitto_passwd -b /mosquitto/config/passwd '${MQTT_BACKEND_USER:-backend}' '${MQTT_BACKEND_PASSWORD}' && mosquitto_passwd -b /mosquitto/config/passwd '${MQTT_SAMPLE_DEVICE_USER:-wms-001}' '${MQTT_SAMPLE_DEVICE_PASSWORD}'"

# Strip Windows CRLF on config/acl files
tr -d '\r' < "${PASSWD_FILE}" > "${PASSWD_FILE}.lf"
cat "${PASSWD_FILE}.lf" > "${PASSWD_FILE}"
rm -f "${PASSWD_FILE}.lf"
if [ -f "${REPO_ROOT}/deployment/mosquitto/acl_file" ]; then
    tr -d '\r' < "${REPO_ROOT}/deployment/mosquitto/acl_file" > "${REPO_ROOT}/deployment/mosquitto/acl_file.lf"
    cat "${REPO_ROOT}/deployment/mosquitto/acl_file.lf" > "${REPO_ROOT}/deployment/mosquitto/acl_file"
    rm -f "${REPO_ROOT}/deployment/mosquitto/acl_file.lf"
fi
if [ -f "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf" ]; then
    tr -d '\r' < "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf" > "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf.lf"
    cat "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf.lf" > "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf"
    rm -f "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf.lf"
fi

chmod 600 "${PASSWD_FILE}" 2>/dev/null || true
echo "[init_mosquitto_passwd] Created Mosquitto password file for '${MQTT_BACKEND_USER:-backend}' and '${MQTT_SAMPLE_DEVICE_USER:-wms-001}' (passwords hidden)."
