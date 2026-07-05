#!/usr/bin/env bash

set -euo pipefail

# constants
APP_DIR="/home/eepy/eepy.page-backend"
SCRIPTS_DIR="${APP_DIR}/scripts"

ENV_FILE="${APP_DIR}/.env"

SERVICE_NAME="eepy-page-backend.service"
SERVICE_SRC="${SCRIPTS_DIR}/${SERVICE_NAME}"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}"
SERVICE_HASH_MARKER="/etc/systemd/system/${SERVICE_NAME}.sha256"

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

required_packages=(ca-certificates curl git gnupg python3 python3-venv python3-pip python3-dev debian-keyring debian-archive-keyring apt-transport-https)
missing_packages=()
for package in "${required_packages[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        missing_packages+=("$package")
    fi
done
if [ "${#missing_packages[@]}" -gt 0 ]; then
    echo "Installing missing system packages: ${missing_packages[*]}"
    apt-get update -qq > /dev/null
    apt-get install -qq -y "${missing_packages[@]}" > /dev/null
fi

python_version="$(python3 -c 'import sys;print(".".join(map(str,sys.version_info[:2])),flush=True)')"
supported_versions=("3.12" "3.13" "3.14")
if [[ ! " ${supported_versions[*]} " =~ " ${python_version} " ]]; then
    echo "Python ${python_version} does not meet the minimum requirement of 3.12. You may experience issues with the backend." >&2
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

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list

    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    apt-get update -qq > /dev/null
    apt-get install -qq -y caddy > /dev/null
else
    echo "Caddy is already installed."
fi

if [ ! -d "${APP_DIR}/venv" ]; then
    echo "Creating Python virtual environment..."
    runuser -u eepy -- python3 -m venv "${APP_DIR}/venv"
else
    echo "Python virtual environment already exists."
fi

requirements_hash="$(sha256sum "${APP_DIR}/requirements.txt" | cut -d ' ' -f 1)"
requirements_marker="${APP_DIR}/venv/.requirements.sha256"

if [ -f "$requirements_marker" ] && [ "$(cat "$requirements_marker")" = "$requirements_hash" ]; then
    echo "Backend Python dependencies are already up to date."
else
    echo "Installing backend Python dependencies..."
    # run as eepy user since pip shouldnt be run as root
    runuser -u eepy -- "${APP_DIR}/venv/bin/python" -m pip install -q -r "${APP_DIR}/requirements.txt"
    printf "%s\n" "$requirements_hash" >"$requirements_marker"
    chown eepy:eepy "$requirements_marker"
fi

echo "Installing systemd service symlink..."
service_changed=0
service_hash="$(sha256sum "$SERVICE_SRC" | cut -d ' ' -f 1)"
if [ -e "$SERVICE_DEST" ] || [ -L "$SERVICE_DEST" ]; then
    current_target="$(readlink "$SERVICE_DEST" || true)"
    if [ "$current_target" != "$SERVICE_SRC" ]; then
        echo "Refusing to overwrite existing ${SERVICE_DEST}." >&2
        echo "Current target/value: ${current_target:-regular file}" >&2
        exit 1
    else
        echo "Systemd service symlink is already installed."
        if [ ! -f "$SERVICE_HASH_MARKER" ] || [ "$(cat "$SERVICE_HASH_MARKER")" != "$service_hash" ]; then
            service_changed=1
        fi
    fi
else
    ln -s "$SERVICE_SRC" "$SERVICE_DEST"
    service_changed=1
fi

if [ "$service_changed" -eq 1 ]; then
    echo "Reloading systemd..."
    systemctl daemon-reload
    printf "%s\n" "$service_hash" >"$SERVICE_HASH_MARKER"
else
    echo "Systemd reload not needed."
fi

echo "Installing Caddyfile..."
mkdir -p /etc/caddy
rm -f "$CADDYFILE_DEST"
cp "$CADDYFILE_SRC" "$CADDYFILE_DEST"
chown root:root "$CADDYFILE_DEST"
chmod 0644 "$CADDYFILE_DEST"

echo "Adding your .env to Caddy's .service file..."
sudo mkdir -p /etc/systemd/system/caddy.service.d/
cat << 'EOF' | sudo tee /etc/systemd/system/caddy.service.d/override.conf > /dev/null
[Service]
EnvironmentFile=/home/eepy/eepy.page-backend/.env
EOF
sudo systemctl daemon-reload

echo "Validating and starting Caddy..."
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
