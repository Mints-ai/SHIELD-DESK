# ShieldDesk Security Audit, Penetration Testing & Vulnerability Disclosure Guide

**Security Contact:** security@shielddesk.io  
**PGP Key ID:** 0x4D279BC1  
**Safe Harbor:** Active for coordinated vulnerability researchers  

---

## 1. Security Architecture & Threat Model

ShieldDesk is built under a **Fail-Closed, Zero-Trust Principle**:
- **Separation of Duties:** Requester cannot approve their own containment actions.
- **Dual-Control Break-Glass:** Tier 3 destructive operations strictly require two independent administrative approvals.
- **Cryptographic Command Validation:** Endpoint agents independently verify RSA-2048 control-plane signatures before dispatching any OS-level firewall or process command.
- **Immutable Hash-Chain Audit Ledger:** Every state change, approval, login, and agent result writes to a SHA-256 forward-linked chain.

---

## 2. In-Scope Targets for External Penetration Testing

The following endpoints and systems are explicitly in-scope:
1. **API Endpoints:**
   - Multi-tenant isolation testing on `/api/incidents`, `/api/fleet`, `/api/tasks`, `/api/plans`.
   - Replay & race condition testing on `/api/approvals/*` and `/api/auth/*`.
   - Injection testing on `/api/agent/telemetry` and `/api/ingest/siem`.
   - SCIM 2.0 provisioning on `/api/scim/v2/*`.
2. **AI Chat & Investigation Layer:**
   - Prompt injection resistance on `/api/chat`.
   - Indirect prompt injection via malicious telemetry or CVE payloads.
   - Context boundary verification (preventing cross-tenant data leakage via RAG).
3. **Endpoint Agent:**
   - Command signature forgery or tampering against the Go binary.
   - Certificate spoofing during `/api/agent/enroll`.

---

## 3. Out-of-Scope Behaviors

- Denial of Service (DoS/DDoS) attacks against production infrastructure.
- Social engineering of employees or contractors.
- Physical attacks against data centers.
