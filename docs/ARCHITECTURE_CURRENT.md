# ShieldDesk — Enterprise Architecture Specification (Production Ready)

**Document Version:** 2.0.0  
**Target:** [https://github.com/Mints-ai/SHIELD-DESK](https://github.com/Mints-ai/SHIELD-DESK)  
**Date:** 2026-09-30  
**Core Motto:** *PROVE BEFORE YOU ACT*  
**Stack:** Next.js 16 (React 19 App Router), TypeScript 5, Go 1.23 Universal Agent, Python 3 ML/CVE Engine, PostgreSQL + Row-Level Security, Redis, Prometheus.

---

## 1. System Target Architecture

```text
                         SHIELDDESK CLOUD
                                │
                ┌───────────────┴───────────────┐
                │                               │
           WEB CONSOLE                      PUBLIC API
          (Next.js 16)                     (/api/v1/...)
                │                               │
                └───────────────┬───────────────┘
                                │
                       IDENTITY / RBAC (MFA, SSO, SCIM)
                                │
                       TENANT ISOLATION (RLS, Anti-IDOR)
                                │
                      INGESTION GATEWAY (Universal Connectors)
                                │
                     SECURITY EVENT MODEL (Normalized)
                                │
                ┌───────────────┴───────────────┐
                │                               │
         SECURITY DIGITAL TWIN            KNOWLEDGE GRAPH
        (services/security-twin)         (CVE / Mitre ATT&CK)
                │                               │
                └───────────────┬───────────────┘
                                │
                             AI LAYER (LLM Gateway: Gemini / OpenAI / Claude)
                                │
                       DETERMINISTIC TOOLS (Zod Schema Enforced)
                                │
                ┌───────────────┼───────────────┐
                │               │               │
           RISK ENGINE    ATTACK PATH      BLAST RADIUS
         (CVSS/EPSS/ML) (services/attack) (services/blast)
                │               │               │
                └───────────────┼───────────────┘
                                │
                         DECISION ENGINE (ALLOW / DENY / REQUIRE_APPROVAL)
                                │
                          POLICY ENGINE (observe / assist / autopilot)
                                │
                       APPROVAL ENGINE (Tokens, Dual Approval, Anti-Replay)
                                │
                       EXECUTION BROKER (Canonical RSA-2048 Signing)
                                │
                ┌───────────────┴───────────────┐
                │                               │
             WINDOWS                          LINUX
              AGENT                           AGENT
            (Go 1.23)                       (Go 1.23)
                │                               │
                └───────────────┬───────────────┘
                                │
                       VERIFICATION ENGINE (State Proof before Declaring Success)
                                │
                      ┌─────────┴─────────┐
                      │                   │
                   SUCCESS              FAIL
                      │                   │
                  EVIDENCE             ROLLBACK
                      │                   │
                      └─────────┬─────────┘
                                │
                         EVIDENCE VAULT (SHA-256 Merkle Ledger)
                                │
                         AUDIT / REPORTING (SOC 2, ISO 27001)
```

---

## 2. Core Architectural Subsystems

### 2.1 Identity, Tenancy & Safety Guards
- **Multi-Tenancy:** PostgreSQL Row-Level Security (RLS) with foreign key enforcement and tenant-isolated in-memory partitions.
- **Enterprise IAM:** SAML 2.0 / OIDC SSO, SCIM 2.0 automated provisioning, TOTP MFA, and session revocation.
- **Production Safety Guard:** Deterministic gatekeeper actively preventing demo personas, mock scans, or simulated executions in production.

### 2.2 Security Digital Twin (`services/security-twin/`)
- In-memory tenant-partitioned graph store modeling endpoints, servers, APIs, databases, business services, identities, and vulnerabilities.
- Answers real-time dependency, reachability, and isolation simulation queries.

### 2.3 Attack Path & Blast Radius Engines
- **Attack Path (`services/attack-path/`):** Traversal kill chains with mandatory evidence binding and deterministic choke-point calculations.
- **Blast Radius (`services/blast-radius/`):** Evaluates downtime, business impact, and distinguishes measured vs. estimated modes. Escalates to dual approval if blast threshold is exceeded.

### 2.4 Governance & Remediation Engines
- **Decision Engine (`services/decision-engine/`):** Mandatory gateway evaluating tenant boundaries, actor roles, emergency kill switches, blast radius, and prior evidence.
- **Policy Engine (`services/policy-engine/`):** Autonomy tier rule evaluation (`observe`, `assist`, `autopilot`, critical asset exceptions).
- **Verification Engine (`services/verification-engine/`):** Proves host state (process absence, port binding, firewall rules) before declaring remediation success.
- **Rollback Engine (`services/rollback-engine/`):** Automatically restores pre-flight safety snapshots upon verification failure.

### 2.5 AI Gateway & Defense (`services/llm-gateway/`)
- Model-agnostic router for Gemini, OpenAI, Claude, and local Ollama models.
- Strict Zod schema validation on structured AI outputs.
- `PromptInjectionGuard`: Untrusted context boundary tagging, delimiter escaping, and adversarial pattern filtering.

### 2.6 Endpoint Fleet & Cryptographic PKI
- Go 1.23 cross-platform agent supporting Windows (`netsh`) and Linux (`iptables`).
- Control Plane X.509 CA issuing device certificates via mTLS with ASN.1 DER integer leading zero padding.
- RSA-2048 canonical payload signing with nonces and timestamps preventing command replay attacks.

### 2.7 Evidence Vault & Universal Connectors
- **Evidence Vault (`services/evidence-vault/`):** Append-only SHA-256 forward-chained Merkle ledger generating cryptographic compliance packages with an offline Python verifier.
- **Universal Connectors (`services/connectors/`):** Ingestion adapters for Wazuh SIEM, Microsoft Defender, CrowdStrike Falcon, and Webhooks with HMAC-SHA256 signature verification.

---

## 3. Production Readiness & Quality Attestation

```bash
> npx tsc --noEmit
# Exit Code: 0 (TypeScript compilation clean, 0 errors)

> npm test
# Total Tests:  199
# Test Suites:  31
# Passing:      199
# Failing:      0
# Duration:     4.69s
```
