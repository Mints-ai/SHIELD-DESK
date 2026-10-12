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

if [[ "$CONTROL_PLANE_URL" != "https://"* ]] && [ "$CONTROL_PLANE_URL" != "http://localhost:3000" ]; then
    echo "[-] SECURITY ERROR: Control plane URL must use HTTPS in production. Plain HTTP is rejected."
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
if command -v go >/dev/null 2>&1; then
    echo "[*] Compiling ShieldDesk Go Agent binary..."
    go build -ldflags="-s -w" -o "${TARGET_BIN}" ./cmd
    chmod +x "${TARGET_BIN}"
elif [ -f "${TARGET_BIN}" ]; then
    echo "[!] Go compiler not found, using existing pre-built binary: ${TARGET_BIN}"
    chmod +x "${TARGET_BIN}"
else
    echo "[-] Go compiler not found and no pre-built binary exists. Please install Go 1.21+."
    exit 1
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
