#!/bin/bash
#
# Install Artemis as a systemd service.
#
# Usage:
#   sudo ./install_service.sh
#
# What it does:
#   1. Copies artemis.service to /etc/systemd/system/
#   2. Updates WorkingDirectory and ExecStart to match this checkout
#   3. Adds a sudoers rule so the service user can run
#      'systemctl stop artemis' without a password (needed for the
#      web UI shutdown button)
#   4. Enables and starts the service
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_USER="${ARTEMIS_USER:-administrator}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)."
    exit 1
fi

echo "=== Installing Artemis systemd service ==="
echo "  Working directory: ${SCRIPT_DIR}"
echo "  Service user:      ${SERVICE_USER}"
echo ""

# ── 1. Generate the unit file with correct paths ────────────────────
UNIT=/etc/systemd/system/artemis.service

sed \
    -e "s|WorkingDirectory=.*|WorkingDirectory=${SCRIPT_DIR}|" \
    -e "s|ExecStart=.*|ExecStart=${SCRIPT_DIR}/venv/bin/python artemis_server.py|" \
    -e "s|EnvironmentFile=.*|EnvironmentFile=${SCRIPT_DIR}/.env|" \
    -e "s|User=.*|User=${SERVICE_USER}|" \
    -e "s|ReadWritePaths=.*|ReadWritePaths=${SCRIPT_DIR}|" \
    "${SCRIPT_DIR}/artemis.service" > "${UNIT}"

echo "  Installed unit file -> ${UNIT}"

# ── 2. Sudoers: let the service user stop/restart without password ──
SUDOERS=/etc/sudoers.d/artemis
cat > "${SUDOERS}" <<SUDOERS_EOF
# Allow the Artemis service user to stop/restart via the web UI
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl stop artemis, /usr/bin/systemctl restart artemis
SUDOERS_EOF
chmod 0440 "${SUDOERS}"
echo "  Installed sudoers  -> ${SUDOERS}"

# ── 3. Reload, enable, start ────────────────────────────────────────
systemctl daemon-reload
systemctl enable artemis
systemctl start artemis

echo ""
echo "=== Artemis service installed and running ==="
echo ""
echo "  Status:   sudo systemctl status artemis"
echo "  Logs:     sudo journalctl -u artemis -f"
echo "  Stop:     sudo systemctl stop artemis"
echo "  Restart:  sudo systemctl restart artemis"
echo ""
