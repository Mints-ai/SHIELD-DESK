# ShieldDesk — Linux Endpoint Agent Architecture & Deployment Guide

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Code Reference:** `agent/cmd/main.go`, `agent/deploy-agent.sh`, `src/lib/fleet/capabilities.ts`  
**Supported Distributions:** Ubuntu 20.04+, Debian 11+, RHEL 8+, Rocky Linux 8+, AlmaLinux 9, Amazon Linux 2023 (x86_64, aarch64)

---

## 1. Overview & Architecture

The ShieldDesk Universal Endpoint Agent on Linux is a standalone statically compiled Go binary (`shielddesk-agent`) that operates as a systemd background service. It collects kernel telemetry, provides live process monitoring, and enforces cryptographically signed containment and remediation directives.

```
+-----------------------------------------------------------------------------------+
|                         Linux Host Execution Environment                          |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Systemd Service: shielddesk-agent.service]                                      |
|  - Capabilities: CAP_NET_ADMIN, CAP_KILL, CAP_SYS_PTRACE                          |
|  - Hardening: ProtectSystem=strict, PrivateTmp=true, ProtectHome=read-only        |
|  - Cryptographic Identity: RSA-2048 keypair in /etc/shielddesk/certs/ (0600)      |
|                                                                                   |
|         |                                 |                                |      |
|         v                                 v                                v      |
|  [Network Isolation]             [Process Containment]            [Telemetry]     |
|  iptables / nftables             SIGTERM / SIGKILL                /proc & /sys    |
|  SHIELDDESK_ISOLATE chain        cgroup v2 freezer                eBPF / auditd   |
|  Control plane pinhole           Process tree analysis            Syslog / journal|
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Capabilities Matrix (Linux)

As defined in `src/lib/fleet/capabilities.ts`:

| Capability Name | Risk Level | Approval Level | Verification Method | Rollback Supported | Linux Execution Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `network.isolate` | `high` | Level 2 | `firewall_rule_check` | Yes | `iptables -I OUTPUT -j DROP; iptables -I OUTPUT -d <control_plane_ip> -j ACCEPT` |
| `network.restore` | `low` | Level 2 | `firewall_rule_check` | No | `iptables -D OUTPUT -j DROP` or flush `SHIELDDESK_ISOLATE` chain |
| `process.terminate`| `medium`| Level 2 | `process_table_check` | Yes (Restart) | `kill -15 <pid>` followed by `kill -9 <pid>` |
| `process.inspect` | `low` | Level 0 | `process_table_check` | No | Ingestion from `/proc/<pid>/status` and `/proc/<pid>/cmdline` |
| `snapshot.create` | `low` | Level 1 | `service_health_check`| No | Save iptables state (`iptables-save > /var/lib/shielddesk/snapshots/<id>.rules`) |
| `snapshot.restore`| `medium`| Level 2 | `service_health_check`| No | Re-apply saved state (`iptables-restore < /var/lib/shielddesk/snapshots/<id>.rules`) |
| `patch.apply` | `medium`| Level 2 | `package_version_check`| Yes | Distribution package manager (`apt-get install --only-upgrade <pkg>` or `dnf upgrade <pkg>`) |
| `service.restart` | `medium`| Level 2 | `service_health_check`| Yes | `systemctl restart <unit>` |
| `file.quarantine` | `medium`| Level 2 | `service_health_check`| Yes | `chmod 0000 <path>; mv <path> /var/lib/shielddesk/quarantine/` |
| `firewall.block` | `low` | Level 1 | `firewall_rule_check` | Yes | `iptables -I INPUT -s <target_ip> -j DROP` |

---

## 3. Deployment & Systemd Service

### One-Line Shell Enrollment (`agent/deploy-agent.sh`)

```bash
sudo ./deploy-agent.sh "https://app.shielddesk.io" "tenant-acme-prod" "$(hostname)"
```

### Systemd Unit Specification (`/etc/systemd/system/shielddesk-agent.service`)

```ini
[Unit]
Description=ShieldDesk Universal Endpoint Agent
Documentation=https://docs.shielddesk.io/agent/linux
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/shielddesk-agent \
  -control-url https://app.shielddesk.io \
  -tenant-id tenant-acme-prod \
  -agent-id auto \
  -hostname %H

Restart=always
RestartSec=5s
KillMode=process

# Security Hardening & Sandboxing
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start via:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now shielddesk-agent
```

---

## 4. Verification and Rule 3 Compliance

When an action like `network.isolate` is issued:
1. The agent executes the underlying iptables / nftables command.
2. Even if exit code is 0, the agent tests physical network isolation:
   - Outbound probe to external gateway (`8.8.8.8:53`) must fail (timeout / dropped).
   - Inbound probe to control plane URL must succeed (`200 OK`).
3. Only upon satisfying both conditions does the agent report `status: "VERIFIED"`.
