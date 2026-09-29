# ShieldDesk Platform Architecture Specification

---

## 1. System Overview

ShieldDesk bridges continuous threat intelligence and deterministic endpoint remediation through an authoritative three-tier design:

```
┌─────────────────────────────────────────────────────────────┐
│                 ShieldDesk Web Console & API                │
│    (Next.js 16 • React 19 • App Router • Server Actions)    │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
                ▼                             ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│   Governance & Audit Core    │ │   Autonomous AI Engine     │
│ • Replay-Proof Tokens        │ │ • Tool-Bounded Analysis    │
│ • Separation of Duties       │ │ • Context Isolation        │
│ • SHA-256 Hash-Chain Ledger  │ │ • Autonomy Tier Classifier │
└───────────────┬──────────────┘ └────────────┬───────────────┘
                │                             │
                └──────────────┬──────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              PostgreSQL + TimescaleDB Cluster               │
│  (Multi-Tenant Schemas • Relational State • Metric Streams) │
└──────────────────────────────┬──────────────────────────────┘
                               │ mTLS / Token Streaming
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Universal Endpoint Agents (Go 1.23)             │
│  (Windows Netsh • Linux Iptables • Process Harvesters)       │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Cryptographic Security Invariants

1. **Immutable Audit Ledger:** Every state-altering action appends a block linking `previous_hash`, `timestamp`, `actor_id`, and `payload` using SHA-256 forward-chaining.
2. **RSA-2048 Command Signing:** The control plane signs remediation instructions using a private key; the agent independently verifies signatures against the control plane's public key before touching OS firewalls or processes.
3. **Separation of Duties:** Requesters of Tier 2 & Tier 3 containment cannot approve their own requests.
4. **Mandatory MFA:** Administrative actions and containment sign-offs require active TOTP enrollment under production fail-closed policy.
