#!/usr/bin/env bash

set -euo pipefail

# ==================================================================================
# eepy.page backend database backup script
# ==================================================================================
# Usage:
#   backup-postgres.sh             Run a backup right now
#   backup-postgres.sh --install   Install daily cronjob to backup db
# 
# Optional environment vars:
#   ENV_FILE                       Path to a .env file (default: <repo>/.env)
#   BACKUP_DIR                     Directory for backups (default: $HOME/db-backups)
#   RETENTION_DAYS                 Days to keep backups (default: 30)
#   PG_CONTAINER                   Docker container name if pg_dump isn't installed
#                                     (default: 'postgres' or 'eepy-page-postgres')
#   CRON_SCHEDULE                  Cron schedule expr (default: "0 1 * * *")
# ==================================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"

ENV_FILE="${ENV_FILE:-${APP_DIR}/.env}"
BACKUP_DIR="${BACKUP_DIR:-${HOME}/db-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
CRON_SCHEDULE="${CRON_SCHEDULE:-0 1 * * *}"
CRON_MARKER="# auto-generated - do not remove this or the following line"

install_cron() {
    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${BACKUP_DIR}"

    local log_file="${BACKUP_DIR}/backup.log"
    local cron_line="${CRON_SCHEDULE} ${SCRIPT_PATH} >> ${log_file} 2>&1 ${CRON_MARKER}"

    local existing_cron
    existing_cron="$(crontab -l 2>/dev/null || true)"

    if printf '%s\n' "${existing_cron}" | grep -Fq "${CRON_MARKER}"; then
        printf '%s\n' "${existing_cron}" | grep -Fv "${CRON_MARKER}" | { cat; printf '%s\n' "${cron_line}"; } | crontab -
        echo "Updated existing daily backup cron job (${CRON_SCHEDULE} UTC)."
    else
        {
            if [ -n "${existing_cron}" ]; then
                printf '%s\n' "${existing_cron}"
            fi
            printf '%s\n' "${cron_line}"
        } | crontab -
        echo "Installed daily backup cron job (${CRON_SCHEDULE} UTC)."
    fi

    echo "Backups directory : ${BACKUP_DIR}"
    echo "Log file          : ${log_file}"
    echo "Retention         : ${RETENTION_DAYS} days"
    echo ""
    echo "Current crontab:"
    crontab -l
}

run_backup() {
    umask 077

    if [ ! -f "${ENV_FILE}" ]; then
        echo "[$(date -u +%FT%TZ)] ERROR: .env file not found at ${ENV_FILE}" >&2
        exit 1
    fi

    local raw_url
    raw_url="$(grep -E '^[[:space:]]*(export[[:space:]]+)?POSTGRES_URL=' "${ENV_FILE}" | tail -n 1 | cut -d '=' -f 2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" || true)"

    if [ -z "${raw_url}" ]; then
        echo "[$(date -u +%FT%TZ)] ERROR: POSTGRES_URL is not set in ${ENV_FILE}" >&2
        exit 1
    fi

    local pg_url="${raw_url/postgresql+psycopg:\/\//postgresql://}"
    pg_url="${pg_url/postgresql+psycopg2:\/\//postgresql://}"
    pg_url="${pg_url/postgres:\/\//postgresql://}"

    local pg_host="" pg_port="" pg_db="" pg_user="" pg_pass=""
    eval "$(python3 - "${pg_url}" <<'PY'
import shlex, sys
from urllib.parse import unquote, urlparse
u = urlparse(sys.argv[1])
print(f"pg_host={shlex.quote(u.hostname or 'localhost')}")
print(f"pg_port={shlex.quote(str(u.port or 5432))}")
print(f"pg_db={shlex.quote((u.path or '').lstrip('/'))}")
print(f"pg_user={shlex.quote(unquote(u.username or ''))}")
print(f"pg_pass={shlex.quote(unquote(u.password or ''))}")
PY
    )"

    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${BACKUP_DIR}"

    local timestamp
    timestamp="$(date -u +%Y%m%d_%H%M%SZ)"
    local dump_file="${BACKUP_DIR}/eepy_page_${timestamp}.dump"
    local tmp_file="${dump_file}.tmp"
    local pgpass_file
    pgpass_file="$(mktemp)"
    chmod 600 "${pgpass_file}"
    printf '%s:%s:%s:%s:%s\n' "${pg_host}" "${pg_port}" "${pg_db}" "${pg_user}" "${pg_pass}" > "${pgpass_file}"

    trap 'rm -f "${tmp_file}" "${pgpass_file}"' EXIT

    echo "[$(date -u +%FT%TZ)] Starting PostgreSQL backup..."

    if command -v pg_dump >/dev/null 2>&1; then
        PGPASSFILE="${pgpass_file}" pg_dump --format=custom --compress=9 --no-owner --no-privileges \
            --host="${pg_host}" --port="${pg_port}" --username="${pg_user}" --dbname="${pg_db}" \
            --file="${tmp_file}"
    elif command -v docker >/dev/null 2>&1; then
        local container="${PG_CONTAINER:-}"
        if [ -z "${container}" ]; then
            for candidate in postgres eepy-page-postgres eepy-page-postgres-local; do
                if docker ps --format '{{.Names}}' | grep -Fxq "${candidate}"; then
                    container="${candidate}"
                    break
                fi
            done
        fi
        if [ -z "${container}" ]; then
            echo "[$(date -u +%FT%TZ)] ERROR: pg_dump not found locally and no running Postgres Docker container matched. Set PG_CONTAINER=<name>." >&2
            exit 1
        fi

        docker exec -e "PGPASSWORD=${pg_pass}" "${container}" pg_dump --format=custom --compress=9 --no-owner --no-privileges --username="${pg_user}" --dbname="${pg_db}" > "${tmp_file}"
    else
        echo "[$(date -u +%FT%TZ)] ERROR: Neither pg_dump nor docker is installed." >&2
        exit 1
    fi

    if [ ! -s "${tmp_file}" ]; then
        echo "[$(date -u +%FT%TZ)] ERROR: Backup file is empty; aborting." >&2
        exit 1
    fi

    chmod 600 "${tmp_file}"
    mv "${tmp_file}" "${dump_file}"
    rm -f "${pgpass_file}"
    trap - EXIT

    local size
    size="$(du -h "${dump_file}" | cut -f 1)"
    echo "[$(date -u +%FT%TZ)] Backup complete: ${dump_file} (${size})"

    local pruned
    pruned="$(find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'eepy_page_*.dump' -mtime "+${RETENTION_DAYS}" -print -delete | wc -l | tr -d ' ')"
    if [ "${pruned}" -gt 0 ]; then
        echo "[$(date -u +%FT%TZ)] Pruned ${pruned} backup(s) older than ${RETENTION_DAYS} days."
    fi
}

case "${1:-}" in
    --install)
        install_cron
        ;;
    -h|--help)
        sed -n '5,19p' "$0"
        ;;
    "")
        run_backup
        ;;
    *)
        echo "Unknown option: $1 (run --help for help)" >&2
        exit 2
        ;;
esac
