# Endpoint OS validation matrix

**Status: BLOCKED-ON-HUMAN.** These tests require dedicated disposable hosts or VMs and a signed agent build. Simulated agent tests do not satisfy this matrix.

## Required platforms

| Family | Versions |
|---|---|
| Ubuntu | 22.04 LTS, 24.04 LTS |
| Debian | Current supported stable release (record exact point release) |
| RHEL-compatible | Supported RHEL and Rocky Linux releases (record exact versions) |
| Windows client | Windows 10 and Windows 11 supported builds |
| Windows Server | Each supported Server release (record exact versions) |

## Per-platform cases

For each OS/version and supported architecture, record agent build hash, OS patch level, test date, operator, tenant, installation ID, and certificate serial.

| Case | Procedure | Evidence to retain |
|---|---|---|
| Install/uninstall | Clean install, permissions, service registration, clean removal | Installer logs, service status, package hash |
| Enroll | Tenant + installation ID + device identity + certificate + entitlement | Redacted request/response, certificate identity/expiry, server audit ID |
| Heartbeat/offline | Normal heartbeat, network outage, reconnect and recovery | Heartbeat timestamps, queue state, reconnect timeline |
| Command | Read-only and approved low-risk command through broker | Decision/policy/approval IDs, signed command, nonce and lifecycle events |
| Verify | Positive and negative post-state proof | Raw host evidence, verifier result, evidence chain references |
| Rollback | Approved rollback on a controlled reversible change | Before/after snapshots and host state; do not infer success from control-plane text |
| Upgrade/downgrade | Signed package, integrity failure, canary failure, supported rollback | Manifest/signature/checksum, service health, audit evidence |
| Certificate rotation | Rotate, overlap policy, revoke old cert, reject old identity | Old/new serial, revocation result, handshake logs |

Run each destructive case on a disposable host with an operator-approved recovery path. Repeat after reboot and after a full agent restart. File results and failures per cell; unsupported OS/version combinations must be explicitly documented rather than inferred.
