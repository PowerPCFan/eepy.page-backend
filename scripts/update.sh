#!/usr/bin/env bash
set -euo pipefail

echo "==========================================="
echo "       ~ eepy-page-backend Updater ~       "
echo "==========================================="

# Ensure script is run with sudo
if [ "${EUID}" -ne 0 ]; then
    echo "Please run this script with sudo." >&2
    exit 1
fi

FULL_REPO_PATH=$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd))
REPO_BASENAME=$(basename "$FULL_REPO_PATH")

cd "$FULL_REPO_PATH"

# Safe directory in case sudo user differs from repo owner
git config --global --add safe.directory "$FULL_REPO_PATH" 2>/dev/null || true

# 1. Backup with current date timestamp to ../
echo "Backing up..."
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
cd ".."
cp -R "$FULL_REPO_PATH" "${REPO_BASENAME}_backup_${TIMESTAMP}"

# Fix backup ownership if run via sudo by a normal user
if [ -n "${SUDO_USER:-}" ]; then
    chown -R "${SUDO_USER}:${SUDO_USER}" "${REPO_BASENAME}_backup_${TIMESTAMP}" 2>/dev/null || true
fi

echo "Created backup: ../${REPO_BASENAME}_backup_${TIMESTAMP}"

# 2. Git pull
echo "Pulling latest changes..."
cd "$FULL_REPO_PATH"
if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" git pull
else
    git pull
fi

# 3. Install requirements into venv
echo "Installing dependencies from requirements.txt..."
VENV_PIP="$FULL_REPO_PATH/venv/bin/pip"

if [ ! -x "$VENV_PIP" ]; then
    echo "❌ Error: Virtual environment pip not found at $VENV_PIP" >&2
    exit 1
fi

if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" "$VENV_PIP" install -r requirements.txt
else
    "$VENV_PIP" install -r requirements.txt
fi

# 4. Restart systemd service
echo "Restarting service..."
systemctl restart eepy-page-backend

echo "==========================================="
echo "  Update complete & backend restarted! 🎉  "
echo "==========================================="
