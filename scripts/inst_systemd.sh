#!/usr/bin/env bash
if [ -z "${BASH_VERSION-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

# inst_systemd.sh - installer placed under scripts/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
UNIT_NAME="wmail.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

echo "wMailServer systemd installer"
echo "Project dir: ${WORKDIR}"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script needs to write to /etc/systemd/system and control systemd."
  echo "Please run as root or via sudo: sudo ${SCRIPT_DIR}/inst_systemd.sh"
  exit 1
fi

if [ -f "${UNIT_PATH}" ]; then
  ts=$(date +%s)
  echo "Backing up existing unit to ${UNIT_PATH}.bak.${ts}"
  cp -a "${UNIT_PATH}" "${UNIT_PATH}.bak.${ts}"
fi

echo "Writing systemd unit to ${UNIT_PATH}"
cat > /tmp/${UNIT_NAME} <<EOF
[Unit]
Description=wMailServer - Simple SMTP/POP3 server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${WORKDIR}
# NOTE: ExecStart uses the exact command you requested
ExecStart=/usr/bin/sudo python3 ${WORKDIR}/wMailServer.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
# Run as root by default (systemd runs ExecStart as root), change User= if you created a less-privileged user
User=root

[Install]
WantedBy=multi-user.target
EOF

mv /tmp/${UNIT_NAME} "${UNIT_PATH}"
chmod 644 "${UNIT_PATH}"

echo "Reloading systemd and enabling service"
systemctl daemon-reload
systemctl enable --now ${UNIT_NAME}

echo "Service ${UNIT_NAME} enabled and started (if no error)."
echo "Status:"
systemctl status ${UNIT_NAME} --no-pager

echo
echo "To follow logs: journalctl -u ${UNIT_NAME} -f"
echo "If you need to remove the unit: sudo systemctl disable --now ${UNIT_NAME} && sudo rm ${UNIT_PATH} && sudo systemctl daemon-reload"

exit 0
