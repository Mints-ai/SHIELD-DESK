# ShieldDesk — Comprehensive STRIDE Threat Model

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Scope:** Control Plane, Edge Ingress, Fleet Agent, AI Gateway, Evidence Vault, and Multi-Tenant Database.

---

## 1. System Decomposition & Attack Surface

The ShieldDesk architecture comprises four primary trust boundaries:
1. **External Ingress:** Web UI, REST APIs, Webhook receivers (Stripe, SIEMs).
2. **Fleet Communication Plane:** mTLS tunnel between Universal Go Agents and the Control Plane.
3. **AI Gateway & Processing:** Boundaries separating tenant telemetry from external LLMs (Google, OpenAI, Anthropic).
4. **Data Plane & Evidence Vault:** Multi-tenant PostgreSQL with Row-Level Security (RLS) and Merkle hash chain logs.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Target Component | Threat Scenario | Mitigation & Architectural Control | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Agent Telemetry | Malicious actor poses as legitimate endpoint agent to inject fake telemetry. | mTLS client certificates, hardware-bound keys (TPM), and tenant ID cryptographic attestation. | `tests/agent-capabilities-and-replay-defense.test.ts` |
| **Spoofing** | Control Plane Command | Attacker intercepts network to issue forged remediation directives (e.g., kill process). | RSA-2048 / Ed25519 digital signatures on all commands with unique UUID nonces and short expiration windows. | `tests/agent-capabilities-and-replay-defense.test.ts` |
| **Tampering** | Remediation Audit Log | Rogue insider attempts to alter or delete execution history of a disruptive action. | Tamper-evident Merkle tree hash chain in Evidence Vault with immutable external anchoring. | `tests/immutable-audit-and-hash-chain.test.ts` |
| **Tampering** | LLM Context Injection | Attacker places prompt injection in Syslog/ETW to trick AI into proposing malicious actions. | `PromptInjectionGuard` regex filtering, `<untrusted_context>` entity boundary escaping, and Zod output schema enforcement. | `tests/ai-gateway-and-evaluation.test.ts` |
| **Repudiation** | Tier 3 High-Impact Approval | Operator denies approving a critical production network isolation action. | Dual-approval cryptographically signed tokens (`ApprovalTokenService`) binding actor ID, action payload, and timestamp. | `tests/governance-and-autonomy.test.ts` |
| **Information Disclosure** | Multi-Tenant Database | Tenant A exploits IDOR or SQL injection to read alerts, agents, or credentials of Tenant B. | PostgreSQL Row-Level Security (RLS) forced on all tables, automated tenant context validation in query middleware, zero cross-tenant leakage. | `tests/multi-tenancy-and-rls.test.ts` |
| **Denial of Service** | Telemetry Ingestion API | Attacker floods `/api/fleet/heartbeat` to exhaust backend connection pool and CPU. | Token bucket rate limiting (`src/lib/security/rateLimit.ts`), Cloudflare edge DDoS mitigation, Kafka/Redis buffer queues. | `tests/rate-limiting.test.ts` |
| **Elevation of Privilege** | RBAC Role Escalation | `SecurityAnalyst` modifies authorization role to `SecurityAdmin` via API parameter tampering. | Strict 7-tier canonical RBAC checks (`src/lib/auth/rbac.ts`), role immutability in user session tokens, separation of duties. | `tests/enterprise-auth-identity-and-rbac.test.ts` |

---

## 3. High-Risk Attack Scenarios & Mitigations

### Scenario 1: Compounding Automated Remediation Loop (Blast Radius Cascade)
- **Risk:** An automated Tier 1 playbook isolates a domain controller or primary database due to a false-positive alert, causing enterprise-wide downtime.
- **Defense:**
  1. **Crown Jewel Protection:** Domain controllers, database primaries, and hypervisors are tagged `critical_infrastructure`, prohibiting autonomous Tier 1 actions.
  2. **Security Digital Twin Simulation:** Every action is simulated against the dependency graph before execution.
  3. **Blast Radius Engine:** If the calculated impact exceeds tenant safety thresholds, the action is blocked and escalated to human approval (Tier 2/3).

### Scenario 2: Replay of Expired Command Nonces
- **Risk:** An adversary captures a legitimate signed command from network traffic and re-executes it hours later.
- **Defense:**
  1. The agent checks command expiration (`expiresAt < now()`). Commands expire after 300 seconds.
  2. The agent verifies the nonce against an in-memory deduplication set. Replays are dropped immediately with an alert emitted.
