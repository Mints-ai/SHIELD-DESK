# ShieldDesk Universal Endpoint Agent Specification

The ShieldDesk Universal Endpoint Agent is a lightweight, cross-platform daemon written in Go 1.23.

---

## 1. Supported Operating Systems

- **Windows:** Windows 10, Windows 11, Windows Server 2016/2019/2022 (x86_64).
- **Linux:** Ubuntu 20.04+, Debian 11+, RHEL 8+, Rocky Linux 9+, Amazon Linux 2023 (x86_64, aarch64).
- **macOS:** macOS Monterey (12)+ on Apple Silicon (arm64).

---

## 2. Agent Core Capabilities

| Capability | Windows Implementation | Linux Implementation |
|---|---|---|
| **Safety Snapshotting** | Netsh advfirewall export + routing table dump | `iptables-save` + `ip route` dump |
| **Host Network Isolation** | Blocks outbound traffic while keeping management port open | Injects `iptables` drop rules preserving management CIDR |
| **Process Termination** | `taskkill /F /PID <pid>` (blocks PID 0, PID 1, and agent self-PID) | `kill -9 <pid>` (protects PID 1 and agent self-PID) |
| **IP Blocking** | Windows Advanced Firewall inbound/outbound drop rules | `iptables -A INPUT/OUTPUT -s/d <ip> -j DROP` |
| **Rollback** | Netsh advfirewall import from safety snapshot file | Restores previous `iptables` ruleset cleanly |
| **Telemetry Harvesting** | Native WMI / PSAPI enumeration and connection tracking | `/proc` inspection and netstat socket enumeration |

---

## 3. Cryptographic Verification Command Flow

```
Control Plane                      Endpoint Agent
      │                                  │
      │ 1. Signs Payload (RSA-2048)      │
      ├─────────────────────────────────>│
      │                                  │ 2. Computes SHA-256 Digest
      │                                  │ 3. rsa.VerifyPKCS1v15(...)
      │                                  │    [If Invalid: REJECTS & Reports Failure]
      │                                  │ 4. Captures Safety Snapshot
      │                                  │ 5. Executes OS Command
      │ 6. Signs Execution Report        │
      │<─────────────────────────────────┤
      │                                  │
[Logs Truthful Event to Hash Chain]
```
