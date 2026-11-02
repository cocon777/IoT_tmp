#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
EXAMPLE_FILE="${REPO_ROOT}/.env.example"

if [ -f "${ENV_FILE}" ]; then
    echo "[make_env] .env already exists at ${ENV_FILE}. Skipping generation."
    exit 0
fi

if [ ! -f "${EXAMPLE_FILE}" ]; then
    echo "[make_env] ERROR: .env.example not found at ${EXAMPLE_FILE}" >&2
    exit 1
fi

MYSQL_ROOT_PW="$(openssl rand -hex 16)"
MYSQL_PW="$(openssl rand -hex 16)"
JWT_SEC="$(openssl rand -hex 32)"
MQTT_BE_PW="$(openssl rand -hex 16)"
MQTT_DYN_PW="$(openssl rand -hex 16)"
MQTT_DEV_PW="$(openssl rand -hex 16)"

cat > "${ENV_FILE}" <<EOF
# MySQL Configuration (auto-generated locally - DO NOT COMMIT)
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PW}
MYSQL_DATABASE=wms_db
MYSQL_USER=wms_user
MYSQL_PASSWORD=${MYSQL_PW}

# JWT Authentication
JWT_SECRET=${JWT_SEC}
JWT_EXPIRE_MINUTES=30

# MQTT Broker Configuration
MQTT_HOST=mosquitto
MQTT_PORT=1883
MQTT_BACKEND_USER=backend
MQTT_BACKEND_PASSWORD=${MQTT_BE_PW}
MQTT_DYNSEC_ADMIN_USER=dynsec_admin
MQTT_DYNSEC_ADMIN_PASSWORD=${MQTT_DYN_PW}
MQTT_SAMPLE_DEVICE_USER=wms-001
MQTT_SAMPLE_DEVICE_PASSWORD=${MQTT_DEV_PW}
EOF

chmod 600 "${ENV_FILE}" 2>/dev/null || true
echo "[make_env] Generated local .env with random secrets."
