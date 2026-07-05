#!/usr/bin/env bash

set -euo pipefail

# constants
APP_DIR="/home/eepy/eepy.page-backend"
SCRIPTS_DIR="${APP_DIR}/scripts"

ENV_FILE="${APP_DIR}/.env"

SERVICE_NAME="eepy-page-backend.service"
SERVICE_SRC="${SCRIPTS_DIR}/${SERVICE_NAME}"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}"

CADDYFILE_SRC="${APP_DIR}/Caddyfile"
CADDYFILE_DEST="/etc/caddy/Caddyfile"

# pre-run checks
if [ "${EUID}" -ne 0 ]; then
    echo "Please run this script with sudo." >&2
    exit 1
fi

if ! id -u eepy >/dev/null 2>&1; then
    echo "User 'eepy' does not exist. Please create it before running this script." >&2
    exit 1
fi

echo "Installing system packages..."
apt-get update
apt-get install -y ca-certificates curl git gnupg python3 python3-venv python3-pip

# special check: clone if not cloned
# actually idk why it wouldnt be cloned since thats how youd access the script but uhh whatever
if [ ! -d "$APP_DIR" ]; then
    echo "Cloning backend repo..."
    runuser -u eepy -- git clone https://github.com/PowerPCFan/eepy.page-backend.git "$APP_DIR"
fi

# enter toplevel repo root
cd "$(git rev-parse --show-toplevel)"

if [ ! -f "$ENV_FILE" ]; then
    echo ".env file missing: ${ENV_FILE}" >&2
    echo "Please create a .env file with the necessary environment variables (use .env.example as reference). After that, run this script again." >&2
    exit 1
fi
if [ ! -f "$SERVICE_SRC" ]; then
    echo "Systemd service file missing: ${SERVICE_SRC}" >&2
    exit 1
fi
if [ ! -f "$CADDYFILE_SRC" ]; then
    echo "Caddyfile missing: ${CADDYFILE_SRC}" >&2
    exit 1
fi

if ! command -v caddy >/dev/null 2>&1; then
    echo "Installing Caddy from the Caddy Debian repos..."

    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list

    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    apt-get update
    apt-get install -y caddy
else
    echo "Caddy is already installed."
fi

if [ ! -d "${APP_DIR}/venv" ]; then
    echo "Creating Python virtual environment..."
    runuser -u eepy -- python3 -m venv "${APP_DIR}/venv"
fi

echo "Installing backend Python dependencies..."
# run as eepy user since pip shouldnt be run as root
runuser -u eepy -- "${APP_DIR}/venv/bin/python" -m pip install -r "${APP_DIR}/requirements.txt"

echo "Installing systemd service symlink..."
if [ -e "$SERVICE_DEST" ] || [ -L "$SERVICE_DEST" ]; then
    current_target="$(readlink "$SERVICE_DEST" || true)"
    if [ "$current_target" != "$SERVICE_SRC" ]; then
        echo "Refusing to overwrite existing ${SERVICE_DEST}." >&2
        echo "Current target/value: ${current_target:-regular file}" >&2
        exit 1
    fi
else
    ln -s "$SERVICE_SRC" "$SERVICE_DEST"
fi

echo "Installing Caddyfile symlink..."
mkdir -p /etc/caddy
if [ -e "$CADDYFILE_DEST" ] || [ -L "$CADDYFILE_DEST" ]; then
    current_target="$(readlink "$CADDYFILE_DEST" || true)"
    if [ "$current_target" != "$CADDYFILE_SRC" ]; then
        backup_path="${CADDYFILE_DEST}.bak.$(date +%Y%m%d%H%M%S)"
        echo "Backing up existing Caddyfile to ${backup_path}"
        mv "$CADDYFILE_DEST" "$backup_path"
        ln -s "$CADDYFILE_SRC" "$CADDYFILE_DEST"
    fi
else
    ln -s "$CADDYFILE_SRC" "$CADDYFILE_DEST"
fi

echo "Reloading systemd and enabling backend service..."
systemctl daemon-reload

echo "Validating and reloading Caddy..."
caddy validate --config "$CADDYFILE_DEST"
systemctl stop caddy
systemctl enable --now caddy

echo
echo "Setup complete."
echo "To start the backend and enable it to start on boot, run:"
echo "  sudo systemctl stop ${SERVICE_NAME} && sudo systemctl enable --now ${SERVICE_NAME}"
echo
echo "View logs with:"
echo "  journalctl -u ${SERVICE_NAME} -f"
