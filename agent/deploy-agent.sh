#!/usr/bin/env bash
set -e

# ==============================================================================
# ShieldDesk Universal Endpoint Agent — Linux Installation & Systemd Enrollment
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

CONTROL_PLANE_URL="${1}"
TENANT_OR_TOKEN="${2}"
HOSTNAME_ID="${3:-$(hostname)}"
AGENT_ID="${4:-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen || echo "agent-$(date +%s)")}"

# Development flag fallback
if [ "$CONTROL_PLANE_URL" = "--dev" ] || [ "$1" = "--dev" ]; then
    CONTROL_PLANE_URL="http://localhost:3000"
    TENANT_OR_TOKEN="${2:-acme-tenant}"
fi

if [ -z "$CONTROL_PLANE_URL" ]; then
    echo "[-] CRITICAL: Control plane URL is required."
    echo "[-] Usage: ./deploy-agent.sh <control_plane_https_url> <tenant_or_token> [hostname] [agent_id]"
    echo "[-] For local lab evaluation: ./deploy-agent.sh --dev [tenant_or_token]"
    exit 1
fi

# Allow HTTPS in production, or localhost/private LAN IPs for lab/dev evaluation
is_allowed_url=0
if [[ "$CONTROL_PLANE_URL" == "https://"* ]] || \
   [[ "$CONTROL_PLANE_URL" == "http://localhost"* ]] || \
   [[ "$CONTROL_PLANE_URL" == "http://127.0.0.1"* ]] || \
   [[ "$CONTROL_PLANE_URL" == "http://192.168."* ]] || \
   [[ "$CONTROL_PLANE_URL" == "http://10."* ]] || \
   [[ "$CONTROL_PLANE_URL" == "http://172."* ]] || \
   [[ "$CONTROL_PLANE_URL" == *.local:* ]] || \
   [[ "$CONTROL_PLANE_URL" == *.local ]]; then
    is_allowed_url=1
fi

if [ "$is_allowed_url" -eq 0 ]; then
    echo "[-] SECURITY ERROR: Control plane URL must use HTTPS in production. Plain HTTP is rejected for non-local addresses."
    exit 1
fi

if [ -z "$TENANT_OR_TOKEN" ]; then
    echo "[-] CRITICAL: Tenant ID or enrollment token is required."
    exit 1
fi


echo "=========================================================="
echo "      SHIELDDESK UNIVERSAL ENDPOINT AGENT (LINUX)         "
echo "=========================================================="
echo "[+] Hostname:      ${HOSTNAME_ID}"
if [[ "${TENANT_OR_TOKEN}" == sdt_* ]]; then
    echo "[+] Enrollment Token: [CONFIGURED - SECURELY REDACTED]"
    AGENT_ARGS="-token ${TENANT_OR_TOKEN} -control-url ${CONTROL_PLANE_URL} -hostname ${HOSTNAME_ID}"
else
    echo "[+] Tenant:        ${TENANT_OR_TOKEN}"
    echo "[+] Agent ID:      ${AGENT_ID}"
    AGENT_ARGS="-control-url ${CONTROL_PLANE_URL} -tenant-id ${TENANT_OR_TOKEN} -agent-id ${AGENT_ID} -hostname ${HOSTNAME_ID}"
fi
echo "[+] Control Plane: ${CONTROL_PLANE_URL}"

# Determine binary destination
if [ "$EUID" -eq 0 ]; then
    TARGET_BIN="/usr/local/bin/shielddesk-agent"
else
    TARGET_BIN="${SCRIPT_DIR}/shielddesk-agent"
fi

# Build Go Agent or use pre-compiled
if command -v go >/dev/null 2>&1 && [ -d "./cmd" ]; then
    echo "[*] Compiling ShieldDesk Go Agent binary..."
    go build -ldflags="-s -w" -o "${TARGET_BIN}" ./cmd
    chmod +x "${TARGET_BIN}"
elif [ -f "${TARGET_BIN}" ]; then
    echo "[!] Using existing binary: ${TARGET_BIN}"
    chmod +x "${TARGET_BIN}"
elif [ -f "${SCRIPT_DIR}/shielddesk-agent" ]; then
    cp "${SCRIPT_DIR}/shielddesk-agent" "${TARGET_BIN}"
    chmod +x "${TARGET_BIN}"
elif [ -f "${SCRIPT_DIR}/../bin/shielddesk-agent" ]; then
    cp "${SCRIPT_DIR}/../bin/shielddesk-agent" "${TARGET_BIN}"
    chmod +x "${TARGET_BIN}"
elif [ -f "${SCRIPT_DIR}/bin/shielddesk-agent-linux-amd64" ]; then
    cp "${SCRIPT_DIR}/bin/shielddesk-agent-linux-amd64" "${TARGET_BIN}"
    chmod +x "${TARGET_BIN}"
else
    echo "[*] Downloading pre-compiled agent binary from control plane..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) GO_ARCH="amd64" ;;
        aarch64|arm64) GO_ARCH="arm64" ;;
        *) GO_ARCH="amd64" ;;
    esac
    if curl -sSfL "${CONTROL_PLANE_URL}/api/agent/binary/linux-${GO_ARCH}" -o "${TARGET_BIN}" 2>/dev/null; then
        echo "[+] Successfully downloaded agent binary for linux-${GO_ARCH}"
        chmod +x "${TARGET_BIN}"
    else
        echo "[-] Go compiler not found and remote binary download failed."
        exit 1
    fi
fi

# Install Systemd service unit if running as root
if [ "$EUID" -eq 0 ]; then
    echo "[*] Configuring systemd service unit..."
    cat <<EOF > /etc/systemd/system/shielddesk-agent.service
[Unit]
Description=ShieldDesk Universal Endpoint Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=${TARGET_BIN} ${AGENT_ARGS}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable shielddesk-agent
    systemctl restart shielddesk-agent
    echo "[+] Systemd service shielddesk-agent successfully started and enabled!"
else
    echo "[*] Non-root execution: starting in background..."
    nohup "${TARGET_BIN}" ${AGENT_ARGS} > /tmp/shielddesk-agent.log 2>&1 &
    echo "[+] Agent running in background (PID: $!). Telemetry logged to /tmp/shielddesk-agent.log."
fi
