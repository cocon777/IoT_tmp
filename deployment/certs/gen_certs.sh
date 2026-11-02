#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"

if [ -f "${ENV_FILE}" ]; then
    set -a
    # shellcheck disable=SC1090
    source <(tr -d '\r' < "${ENV_FILE}")
    set +a
fi

cd "${SCRIPT_DIR}"

FORCE="${1:-}"
if [ -f "ca.crt" ] && [ -f "server.crt" ] && [ -f "server.key" ] && [ "${FORCE}" != "--force" ]; then
    echo "[gen_certs] Certificates already exist in ${SCRIPT_DIR}. Use --force to regenerate."
    exit 0
fi

CN="${MQTT_TLS_CN:-192.168.100.95}"
EXTRA_IP="${MQTT_TLS_SAN_IP:-10.22.0.185}"

cat > "openssl-san.cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = VN
ST = HaNoi
L = HaNoi
O = WMS-IoT-Group
OU = TV3-Security
CN = ${CN}

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_server]
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = mosquitto
DNS.3 = wms-mosquitto
IP.1 = 127.0.0.1
IP.2 = 127.0.0.2
IP.3 = ${CN}
IP.4 = ${EXTRA_IP}
EOF

# 1. Generate Private Root CA
openssl genrsa -out "ca.key" 2048 2>/dev/null
MSYS_NO_PATHCONV=1 openssl req -x509 -new -nodes \
    -key "ca.key" \
    -sha256 -days 3650 \
    -subj "/C=VN/ST=HaNoi/L=HaNoi/O=WMS-IoT-Group/OU=TV3-Root-CA/CN=WMS-Root-CA" \
    -config "openssl-san.cnf" \
    -extensions v3_ca \
    -out "ca.crt"

# 2. Generate Server Key & CSR
openssl genrsa -out "server.key" 2048 2>/dev/null
openssl req -new \
    -key "server.key" \
    -config "openssl-san.cnf" \
    -out "server.csr"

# 3. Sign Server Certificate with Root CA
openssl x509 -req \
    -in "server.csr" \
    -CA "ca.crt" \
    -CAkey "ca.key" \
    -CAcreateserial \
    -out "server.crt" \
    -days 825 -sha256 \
    -extfile "openssl-san.cnf" \
    -extensions v3_server 2>/dev/null

rm -f "server.csr" "ca.srl" "openssl-san.cnf"
chmod 644 "ca.crt" "server.crt" "server.key" 2>/dev/null || true
chmod 600 "ca.key" 2>/dev/null || true

echo "[gen_certs] Generated Root CA (ca.crt) and Server TLS Cert (CN=${CN}, SAN=localhost,mosquitto,127.0.0.1,127.0.0.2,${CN},${EXTRA_IP})."
