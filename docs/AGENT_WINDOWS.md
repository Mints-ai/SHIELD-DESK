# ShieldDesk — Windows Endpoint Agent Architecture & Deployment Guide

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Code Reference:** `agent/cmd/main.go`, `agent/deploy-agent.ps1`, `src/lib/fleet/capabilities.ts`  
**Supported OS:** Windows 10, Windows 11, Windows Server 2016, 2019, 2022 (x86_64, ARM64)

---

## 1. Overview & Architecture

The ShieldDesk Universal Endpoint Agent on Windows is a compiled Go binary (`shielddesk-agent.exe`) designed to execute high-assurance security telemetry collection, continuous health attestation, and cryptographically verified remediation actions.

```
+-----------------------------------------------------------------------------------+
|                        Windows Endpoint Host Environment                          |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ShieldDesk Service Daemon: shielddesk-agent.exe]                                |
|  - Identity: NT AUTHORITY\SYSTEM or Dedicated Service Account                      |
|  - Cryptographic Keypair: RSA-2048 / Ed25519 stored in Windows CNG/DPAPI          |
|  - Mutual TLS (mTLS): In-transit TLS 1.3 encrypted tunnel to Control Plane        |
|                                                                                   |
|         |                                 |                                |      |
|         v                                 v                                v      |
|  [Network Isolation]             [Process Management]             [Telemetry]     |
|  netsh advfirewall               taskkill / PowerShell            ETW / Sysmon    |
|  Outbound Deny All               Terminate Malicious PID          Event Logs      |
|  Management Allowlist            Parent/Child Tracking            WMI / CIM       |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Capabilities Matrix (Windows)

As defined in `src/lib/fleet/capabilities.ts`, the Windows agent implements the following canonical capabilities:

| Capability Name | Risk Level | Approval Level | Verification Method | Rollback Supported | Windows Execution Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `network.isolate` | `high` | Level 2 | `firewall_rule_check` | Yes | `netsh advfirewall firewall add rule name="ShieldDesk_Isolate" dir=out action=block ...` |
| `network.restore` | `low` | Level 2 | `firewall_rule_check` | No | `netsh advfirewall firewall delete rule name="ShieldDesk_Isolate"` |
| `process.terminate`| `medium`| Level 2 | `process_table_check` | Yes (Restart) | `taskkill /F /PID <pid>` or `Stop-Process -Id <pid> -Force` |
| `process.inspect` | `low` | Level 0 | `process_table_check` | No | `Get-CimInstance Win32_Process` |
| `snapshot.create` | `low` | Level 1 | `service_health_check`| No | VSS snapshot / registry export & routing table dump |
| `snapshot.restore`| `medium`| Level 2 | `service_health_check`| No | VSS revert / registry restore |
| `patch.apply` | `medium`| Level 2 | `package_version_check`| Yes | Windows Update WUA API / MSU package install |
| `service.restart` | `medium`| Level 2 | `service_health_check`| Yes | `sc stop <service>` then `sc start <service>` |
| `file.quarantine` | `medium`| Level 2 | `service_health_check`| Yes | ACL lock + move to `C:\ProgramData\ShieldDesk\Quarantine\` |
| `firewall.block` | `low` | Level 1 | `firewall_rule_check` | Yes | `netsh advfirewall firewall add rule name="ShieldDesk_Block_<IP>" ...` |

---

## 3. Deployment & Enrollment

### Automated PowerShell Enrollment (`agent/deploy-agent.ps1`)

Enrollment requires Local Administrator privileges. Run from an elevated PowerShell terminal:

```powershell
.\deploy-agent.ps1 `
  -ControlPlaneUrl "https://app.shielddesk.io" `
  -TenantId "tenant-acme-prod" `
  -Hostname $env:COMPUTERNAME
```

### Windows Service Installation

To register the agent as an automatic Windows Service:

```powershell
# 1. Place binary in secure administrative path
New-Item -ItemType Directory -Path "C:\Program Files\ShieldDesk" -Force
Copy-Item ".\shielddesk-agent.exe" "C:\Program Files\ShieldDesk\shielddesk-agent.exe"

# 2. Register service via Service Control (sc.exe)
sc.exe create ShieldDeskAgent `
  binPath= "C:\Program Files\ShieldDesk\shielddesk-agent.exe -control-url https://app.shielddesk.io -tenant-id tenant-acme-prod -agent-id auto" `
  start= auto `
  DisplayName= "ShieldDesk Universal Endpoint Agent"

# 3. Configure recovery actions on unexpected failure
sc.exe failure ShieldDeskAgent reset= 86400 actions= restart/5000/restart/10000/restart/60000

# 4. Start the service
sc.exe start ShieldDeskAgent
```

---

## 4. Cryptographic Attestation & Replay Defense

1. **Client Certificate Enrollment:** On initial boot, the agent generates an RSA-2048 keypair and transmits a Certificate Signing Request (CSR) to `/api/fleet/enroll`.
2. **Signed Instruction Verification:** Every command dispatched from the control plane includes:
   - Command Payload JSON
   - Unique Nonce (UUIDv4)
   - Expiration Timestamp (strict 300s window)
   - SHA-256 RSA signature signed by the Tenant Private Key
3. **Replay Defense:** The agent maintains an in-memory ring buffer of recent nonces. Duplicate nonces or expired timestamps are dropped immediately.
4. **Local Hardware Root of Trust:** On supported Windows devices, private keys are protected using Windows CNG with TPM 2.0 backing.
