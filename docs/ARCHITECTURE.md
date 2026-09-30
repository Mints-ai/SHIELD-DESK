# ShieldDesk Platform Architecture Specification

---

## 1. System Overview

ShieldDesk bridges continuous threat intelligence and deterministic endpoint remediation through an evidence-driven, zero-bypass architecture centered on the core product principle:

> **PROVE BEFORE YOU ACT.**

```text
┌─────────────────────────────────────────────────────────────┐
│                 ShieldDesk Web Console & API                │
│    (Next.js 16 • React 19 • App Router • Server Actions)    │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
                ▼                             ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│   Governance & Audit Core    │ │   Autonomous AI Gateway    │
│ • Decision & Policy Engines  │ │ • Tool-Bounded Analysis    │
│ • Replay-Proof Tokens        │ │ • Context Isolation (Zod) │
│ • Separation of Duties       │ │ • Prompt Injection Defense │
│ • SHA-256 Merkle Vault       │ │ • Multi-Provider Router    │
└───────────────┬──────────────┘ └────────────┬───────────────┘
                │                             │
                └──────────────┬──────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Digital Twin, Attack Path & Blast Radius        │
│  (Asset Topology Graph • Kill Chains • Choke Point Analysis)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              Verification & Rollback Engines                │
│  (Pre-Flight Safety Snapshot • State Proof • Auto-Revert)   │
└──────────────────────────────┬──────────────────────────────┘
                               │ mTLS (RFC 5280) / Signed RSA-2048
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Universal Endpoint Agents (Go 1.23)             │
│  (Windows Netsh • Linux Iptables • Process Harvesters)      │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Cryptographic Security Invariants

1. **Rule 1 & 2 (Untrusted AI):** The LLM is never the authority. AI recommends; the Decision and Policy engines determine allowed actions. AI output is strictly validated against Zod schemas.
2. **Rule 3 (State Verification):** `PATCH_SUCCESS` is never equivalent to `SECURITY_FIXED`. The Verification Engine proves the post-remediation host state before declaring success.
3. **Automated Governed Rollback:** If post-remediation verification fails, the Rollback Engine automatically restores the pre-execution safety snapshot.
4. **Immutable Audit Ledger & Merkle Vault:** Every state-altering action appends an unbroken SHA-256 link (`current_hash = SHA256(prev_hash | actor_id | payload)`), compiled into verifiable Merkle evidence packages.
5. **RSA-2048 Command Signing & Nonce Replay Defense:** The control plane signs remediation instructions using an RSA-2048 private key; endpoint agents verify signature, nonce, timestamp, and local capabilities before touching host firewalls or processes.
6. **Separation of Duties:** Requesters of Tier 2 & Tier 3 containment cannot approve their own requests; Tier 3 requires dual distinct SuperAdmin authorizations.
7. **Mandatory MFA & Fail-Closed Safety:** Administrative actions, containment sign-offs, and production environments require active TOTP enrollment and strictly fail closed via `ProductionSafetyGuard`.
