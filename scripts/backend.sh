#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/home/eepy/eepy.page-backend"

cd "$APP_DIR"

if [ ! -x "./venv/bin/uvicorn" ]; then
    echo "uvicorn not found at ${APP_DIR}/venv/bin/uvicorn" >&2
    echo "Run: \`${APP_DIR}/venv/bin/python3 -m pip install -r ${APP_DIR}/requirements.txt\`" >&2
    exit 1
fi

export PYTHONUNBUFFERED=1
export PYTHONPATH="${APP_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

exec ./venv/bin/uvicorn server.main:app \
    --host "127.0.0.1" \
    --port "8000" \
    --workers "1" \
    --proxy-headers \
    --forwarded-allow-ips "127.0.0.1"
