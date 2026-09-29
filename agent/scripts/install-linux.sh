#!/usr/bin/env bash
# ShieldDesk Universal Endpoint Agent - Linux Automated Installation Script (systemd)
# Usage:
#   curl -sSL https://control.shielddesk.io/install.sh | sudo bash -s -- --control-plane "https://control.shielddesk.io" --token "sdt_..."

set -euo pipefail

CONTROL_PLANE=""
ENROLL_TOKEN=""
INSTALL_DIR="/opt/shielddesk"
BINARY_PATH="${INSTALL_DIR}/shielddesk-agent"
SERVICE_FILE="/etc/systemd/system/shielddesk-agent.service"

echo "=========================================================="
echo "    ShieldDesk Universal Endpoint Agent - Linux Setup     "
echo "=========================================================="

# 1. Check Root
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (or via sudo)." >&2
   exit 1
fi

# 2. Parse Arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --control-plane)
      CONTROL_PLANE="$2"
      shift 2
      ;;
    --token)
      ENROLL_TOKEN="$2"
      shift 2
      ;;
    *)
      echo "[ERROR] Unknown parameter: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$CONTROL_PLANE" || -z "$ENROLL_TOKEN" ]]; then
  echo "[ERROR] Missing required arguments: --control-plane <url> --token <sdt_token>" >&2
  exit 1
fi

# 3. Create Install Directory
echo "[1/5] Preparing installation directory ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"

# 4. Fetch or Build Binary
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *)
    echo "[ERROR] Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

echo "[2/5] Installing agent binary for linux/${GO_ARCH}..."
DOWNLOAD_URL="${CONTROL_PLANE}/api/agent/binary/linux-${GO_ARCH}"

if curl -sSfL "${DOWNLOAD_URL}" -o "${BINARY_PATH}" 2>/dev/null; then
  echo "[OK] Downloaded pre-compiled binary from control plane."
elif command -v go >/dev/null 2>&1; then
  echo "[WARN] Remote binary unavailable. Compiling locally using Go..."
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  (cd "${SCRIPT_DIR}/../cmd" && go build -o "${BINARY_PATH}" .)
else
  echo "[ERROR] Could not download binary and Go compiler is not installed." >&2
  exit 1
fi

chmod 755 "${BINARY_PATH}"

# 5. Create Systemd Service File
echo "[3/5] Configuring systemd service (${SERVICE_FILE})..."
cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=ShieldDesk Universal Endpoint Agent
Documentation=https://shielddesk.io/docs
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BINARY_PATH} -control-url "${CONTROL_PLANE}" -enroll-token "${ENROLL_TOKEN}"
Restart=always
RestartSec=5s
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF

# 6. Reload and Start Systemd Daemon
echo "[4/5] Reloading systemd and enabling service..."
systemctl daemon-reload
systemctl enable shielddesk-agent.service

echo "[5/5] Starting shielddesk-agent..."
systemctl restart shielddesk-agent.service

sleep 2
if systemctl is-active --quiet shielddesk-agent.service; then
  echo "=========================================================="
  echo " [SUCCESS] ShieldDesk Endpoint Agent is RUNNING as a systemd service!"
  echo " Active and streaming telemetry to:"
  echo " ${CONTROL_PLANE}"
  echo "=========================================================="
else
  echo "[WARNING] Service started but status is not active. Check: journalctl -u shielddesk-agent -n 50"
fi
