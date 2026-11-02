#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EVIDENCE_FILE="${REPO_ROOT}/docs/evidence/s2-401.txt"
API_BASE="${API_BASE:-http://localhost:8000}"

mkdir -p "$(dirname "${EVIDENCE_FILE}")"
: > "${EVIDENCE_FILE}"

log_line() {
    echo "$1" | tee -a "${EVIDENCE_FILE}"
}

log_line "=== KIEM THU BAO MAT S2 (BUOC S5): XAC THUC JWT & LOI 401 ==="
log_line "Target API: ${API_BASE}"
log_line "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log_line "-------------------------------------------------------------"

# 1. Goi /api/me khong co header Authorization -> 401
RES_NO_TOKEN="$(curl -s -i "${API_BASE}/api/me" | tr -d '\r')"
HTTP_NO_TOKEN="$(echo "${RES_NO_TOKEN}" | head -n 1)"
BODY_NO_TOKEN="$(echo "${RES_NO_TOKEN}" | tail -n 1)"
log_line "[1] GET /api/me (Khong co token):"
log_line "    Status: ${HTTP_NO_TOKEN}"
log_line "    Body:   ${BODY_NO_TOKEN}"

# 2. Goi /api/me voi token sai chu ky -> 401
RES_BAD_TOKEN="$(curl -s -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalidsignature" "${API_BASE}/api/me" | tr -d '\r')"
HTTP_BAD_TOKEN="$(echo "${RES_BAD_TOKEN}" | head -n 1)"
BODY_BAD_TOKEN="$(echo "${RES_BAD_TOKEN}" | tail -n 1)"
log_line "[2] GET /api/me (Token sai chu ky):"
log_line "    Status: ${HTTP_BAD_TOKEN}"
log_line "    Body:   ${BODY_BAD_TOKEN}"

# 3. Sinh token da het han trong container va goi /api/me -> 401 (khong in token ra log)
EXPIRED_TOKEN="$(docker exec wms-backend python -c "from datetime import timedelta; from app.security.auth import create_access_token; print(create_access_token(1, 'admin', timedelta(seconds=-30)))" | tr -d '\r')"
RES_EXP_TOKEN="$(curl -s -i -H "Authorization: Bearer ${EXPIRED_TOKEN}" "${API_BASE}/api/me" | tr -d '\r')"
HTTP_EXP_TOKEN="$(echo "${RES_EXP_TOKEN}" | head -n 1)"
BODY_EXP_TOKEN="$(echo "${RES_EXP_TOKEN}" | tail -n 1)"
log_line "[3] GET /api/me (Token da het han exp < now):"
log_line "    Status: ${HTTP_EXP_TOKEN}"
log_line "    Body:   ${BODY_EXP_TOKEN}"

# 4. Dang nhap sai mat khau -> 401 voi thong bao chung
RES_WRONG_PW="$(curl -s -i -X POST "${API_BASE}/api/auth/login" -H "Content-Type: application/json" -d '{"email":"admin@wms.io","password":"wrong_password"}' | tr -d '\r')"
HTTP_WRONG_PW="$(echo "${RES_WRONG_PW}" | head -n 1)"
BODY_WRONG_PW="$(echo "${RES_WRONG_PW}" | tail -n 1)"
log_line "[4] POST /api/auth/login (Sai mat khau):"
log_line "    Status: ${HTTP_WRONG_PW}"
log_line "    Body:   ${BODY_WRONG_PW}"

log_line "-------------------------------------------------------------"
if echo "${HTTP_NO_TOKEN}" | grep -q "401" && \
   echo "${HTTP_BAD_TOKEN}" | grep -q "401" && \
   echo "${HTTP_EXP_TOKEN}" | grep -q "401" && \
   echo "${HTTP_WRONG_PW}" | grep -q "401"; then
    log_line "KET QUA S2: PASS (Tat ca truong hop thieu/sai/het han token deu tra 401)"
    exit 0
else
    log_line "KET QUA S2: FAIL"
    exit 1
fi
