#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"

if [ ! -f "${ENV_FILE}" ]; then
    bash "${SCRIPT_DIR}/make_env.sh"
fi

set -a
# shellcheck disable=SC1090
source <(tr -d '\r' < "${ENV_FILE}")
set +a

# Ensure mosquitto.conf has LF line endings
tr -d '\r' < "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf" > "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf.lf"
cat "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf.lf" > "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf"
rm -f "${REPO_ROOT}/deployment/mosquitto/mosquitto.conf.lf"

# Initialize /mosquitto/data/dynamic-security.json inside the mosquitto volume
MSYS_NO_PATHCONV=1 docker exec wms-mosquitto sh -c "
    rm -f /mosquitto/data/dynamic-security.json &&
    mosquitto_ctrl dynsec init /mosquitto/data/dynamic-security.json '${MQTT_DYNSEC_ADMIN_USER}' '${MQTT_DYNSEC_ADMIN_PASSWORD}' >/dev/null &&
    chown mosquitto:mosquitto /mosquitto/data/dynamic-security.json &&
    chmod 600 /mosquitto/data/dynamic-security.json
"

docker compose -f "${REPO_ROOT}/deployment/docker-compose.yml" restart mosquitto
sleep 2

MSYS_NO_PATHCONV=1 docker exec \
    -e MQTT_SAMPLE_DEVICE_USER="${MQTT_SAMPLE_DEVICE_USER:-wms-001}" \
    -e MQTT_SAMPLE_DEVICE_PASSWORD="${MQTT_SAMPLE_DEVICE_PASSWORD:-}" \
    wms-backend python -c "from app.services.broker_admin import bootstrap_broker_dynsec; bootstrap_broker_dynsec()"

echo "[init_mosquitto_dynsec] Initialized Dynamic Security plugin, roles, backend account, and sample device '${MQTT_SAMPLE_DEVICE_USER:-wms-001}'."
