#!/usr/bin/env bash
set -e

# ==============================================================================
# ShieldDesk Universal Endpoint Agent — Linux Installation & Systemd Enrollment
# ==============================================================================

CONTROL_PLANE_URL="${1:-http://localhost:3000}"
TENANT_ID="${2:-acme-tenant}"
HOSTNAME_ID="${3:-$(hostname)}"
AGENT_ID="${4:-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen || echo "agent-$(date +%s)")}"

echo "=========================================================="
echo "      SHIELDDESK UNIVERSAL ENDPOINT AGENT (LINUX)         "
echo "=========================================================="
echo "[+] Hostname:      ${HOSTNAME_ID}"
echo "[+] Tenant:        ${TENANT_ID}"
echo "[+] Agent ID:      ${AGENT_ID}"
echo "[+] Control Plane: ${CONTROL_PLANE_URL}"

# Build Go Agent
if command -v go >/dev/null 2>&1; then
    echo "[*] Compiling ShieldDesk Go Agent binary..."
    go build -ldflags="-s -w" -o /usr/local/bin/shielddesk-agent cmd/main.go
    chmod +x /usr/local/bin/shielddesk-agent
else
    echo "[-] Go compiler not found. Please compile or provide pre-built binary."
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
ExecStart=/usr/local/bin/shielddesk-agent -control-url ${CONTROL_PLANE_URL} -tenant-id ${TENANT_ID} -agent-id ${AGENT_ID} -hostname ${HOSTNAME_ID}
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
    nohup /usr/local/bin/shielddesk-agent -control-url "${CONTROL_PLANE_URL}" -tenant-id "${TENANT_ID}" -agent-id "${AGENT_ID}" -hostname "${HOSTNAME_ID}" > /tmp/shielddesk-agent.log 2>&1 &
    echo "[+] Agent running in background (PID: $!). Telemetry logged to /tmp/shielddesk-agent.log."
fi
