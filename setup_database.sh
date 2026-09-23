#!/usr/bin/env bash
# ==============================================================================
# ShieldDesk Automated PostgreSQL Setup Script (Linux / macOS)
# ==============================================================================
set -euo pipefail

SUPER_USER="${1:-postgres}"
SUPER_PASS="${2:-shielddesk_dev}"
DB_USER="${3:-shielddesk}"
DB_PASS="${4:-shielddesk_dev}"
DB_NAME="${5:-shielddesk}"
DB_HOST="${6:-127.0.0.1}"
DB_PORT="${7:-5432}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/db/schema.sql"
SEED_FILE="${SCRIPT_DIR}/db/seed.sql"

echo "=========================================================="
echo "         SHIELDDESK POSTGRESQL INITIALIZATION             "
echo "=========================================================="
echo "[+] Host:     ${DB_HOST}:${DB_PORT}"
echo "[+] Database: ${DB_NAME}"
echo "[+] User:     ${DB_USER}"

if ! command -v psql &> /dev/null; then
    echo "[-] Error: 'psql' client not found in PATH. Please install PostgreSQL client tools."
    exit 1
fi

export PGPASSWORD="${SUPER_PASS}"

echo "[*] Creating database role and database if not exists..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${SUPER_USER}" -tc "SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}'" | grep -q 1 || \
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${SUPER_USER}" -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${SUPER_USER}" -tc "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'" | grep -q 1 || \
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${SUPER_USER}" -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${SUPER_USER}" -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"

echo "[*] Applying schema.sql DDL..."
export PGPASSWORD="${DB_PASS}"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f "${SCHEMA_FILE}"

echo "[*] Applying seed.sql telemetry data..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f "${SEED_FILE}"

echo "[+] SUCCESS: ShieldDesk database initialized and seeded successfully!"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "SELECT incident_code, severity, status, title FROM incidents;"
