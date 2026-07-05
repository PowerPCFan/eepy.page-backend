#!/usr/bin/env bash
set -euo pipefail

echo "==========================================="
echo "          ~ Caddyfile Updater ~            "
echo "==========================================="

if [ "${EUID}" -ne 0 ]; then
    echo "Please run this script with sudo." >&2
    exit 1
fi
if [ ! -f "/home/eepy/eepy.page-backend/Caddyfile" ]; then
    echo "Caddyfile source missing: /home/eepy/eepy.page-backend/Caddyfile" >&2
    exit 1
fi

echo "Creating Caddyfile directory..."
mkdir -p "/etc/caddy"

echo "Removing old Caddyfile..."
rm -f "/etc/caddy/Caddyfile"

echo "Copying new Caddyfile..."
cp "/home/eepy/eepy.page-backend/Caddyfile" "/etc/caddy/Caddyfile"

echo "Fixing permissions..."
chown root:root "/etc/caddy/Caddyfile"
chmod 0644 "/etc/caddy/Caddyfile"

echo "==========================================="
echo "  Finished updating /etc/caddy/Caddyfile!  "
echo "==========================================="