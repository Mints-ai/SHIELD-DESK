# ShieldDesk — Enterprise Security Architecture & Cryptographic Standards

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Security Classification:** Public / Enterprise Whitepaper  
**Core Invariant:** Fail-closed by design; defense-in-depth across control plane, edge, and endpoints.

---

## 1. Security Architecture Principles

ShieldDesk is built around the fundamental security premise: **PROVE BEFORE YOU ACT**. All system components operate under zero-trust assumptions with defense-in-depth:

```
+-----------------------------------------------------------------------------------+
|                         ShieldDesk Defense-in-Depth Model                         |
+-----------------------------------------------------------------------------------+
| 1. Perimeter & Ingress   : Cloudflare DDoS, WAF, TLS 1.3 Strict, Rate Limiting    |
| 2. Authentication        : WebAuthn MFA, Enterprise SSO (OIDC/SAML), SCIM 2.0     |
| 3. Authorization         : 7-Tier Canonical RBAC + Separation of Duties           |
| 4. Data Isolation        : Multi-Tenant Schema Partitioning + PostgreSQL RLS      |
| 5. Endpoint Security     : mTLS PKI, RSA-2048 Signed Commands, Nonce Anti-Replay  |
| 6. AI Safety Boundary    : Prompt Injection Guard, Zod Schemas, Citations Grounding|
| 7. Audit & Compliance    : Immutable SHA-256 Merkle Evidence Vault                |
+-----------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Standards

ShieldDesk strictly prohibits deprecated or weak cryptographic algorithms (MD5, SHA-1, DES, 3DES, RC4). The following standards are enforced system-wide:

| Use Case | Cryptographic Algorithm | Key Length / Parameter | Verification / Implementation |
| :--- | :--- | :--- | :--- |
| **In-Transit Encryption** | TLS 1.3 (Fallback to TLS 1.2) | ECDHE-ECDSA / RSA-2048+ | Enforced via HSTS (`max-age=63072000; includeSubDomains; preload`) |
| **Data at Rest** | AES-256-GCM | 256-bit symmetric keys | Envelope encryption with KMS / Cloud KMS |
| **Agent Command Signatures** | RSA-PSS or Ed25519 | RSA-2048 / SHA-256 | `src/lib/fleet/commandSigning.ts` |
| **License Tokens** | HMAC-SHA256 | 256-bit secret | `src/lib/billing/licenses.ts` (Timing-safe comparison) |
| **Password Hashing** | Argon2id / bcrypt | Salt >= 16 bytes, Cost >= 12 | Standard PBKDF implementation |
| **Audit Log Integrity** | Merkle Hash Trees | SHA-256 linear chain | `services/evidence-vault/` tamper-evident ledger |

---

## 3. Strict Fail-Closed Policy (`ProductionSafetyGuard`)

In production environments (`APP_ENV=production` or `NODE_ENV=production`):
1. **Mock Execution Prohibited:** Any attempt to invoke mock remediation executors or synthetic agents immediately fails closed with an unrecoverable exception.
2. **Missing Secrets Block Startup:** If cryptographic secrets (`SHIELDDESK_LICENSE_SECRET`, `NEXTAUTH_SECRET`, `DATABASE_URL`) are missing or match insecure default values, the application terminates immediately.
3. **Dev Personas Rejected:** Dev accounts (e.g., `dev-admin`, `dev-analyst`) cannot authenticate in production. Negative test coverage in `tests/safety-boundary.test.ts` continuously verifies this invariant.

---

## 4. Rate Limiting & Anti-Abuse (`src/lib/security/rateLimit.ts`)

- In-memory token bucket and sliding window rate limiters enforce request limits across API endpoints.
- Unreferenced interval timers (`.unref()`) guarantee resource cleanup without blocking Node.js event loops.
- IP-based and tenant-based rate limits protect authentication endpoints against brute-force attacks.

---

## 5. Vulnerability Disclosure & Bug Bounty

ShieldDesk maintains a coordinated vulnerability disclosure policy:
- **Security Contact:** `security@shielddesk.io`
- **PGP Key:** Fingerprint available at `https://app.shielddesk.io/.well-known/security.txt`
- **Response SLA:** Initial acknowledgment within 24 hours; severity assessment and triage within 72 hours; fix deployment within 7 days for Critical/High findings.
- **Safe Harbor:** Security researchers acting in good faith without exfiltrating customer data are protected under our responsible disclosure terms.
