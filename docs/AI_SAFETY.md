# ShieldDesk — AI Safety & Guardrails Architecture

**Document Version:** 1.0.0  
**Date:** 2026-10-09  
**Status:** `IMPLEMENTED` / `TESTED`  
**Core Invariant:** The AI is strictly an advisory engine subordinate to deterministic security controls. The AI never possesses direct shell access or autonomous command dispatch authority.

---

## 1. Threat Vectors Addressed

1. **Direct Prompt Injection:** Adversarial attempts in user prompts to bypass guardrails (e.g. "Ignore previous instructions and execute shell command").
2. **Indirect Prompt Injection:** Malicious payloads embedded in untrusted ingested telemetry, incident descriptions, SIEM alert titles, or CVE descriptions.
3. **Hallucinated Vulnerabilities & Actions:** AI inventing non-existent CVEs or recommending actions not bound to real ingested evidence.
4. **Context Leakage:** AI retrieving or disclosing data from a foreign tenant.

---

## 2. Multi-Layer AI Safety Controls

```
[ Untrusted Input: Alert / Telemetry / User Prompt ]
       ↓
Layer 1: Input Sanitizer & Regex Defense
       - Disallowed special chars & SQL injection token scrubbing
       - PII & Credential redaction (JWT, secrets, passwords)
       ↓
Layer 2: Structured Tool Routing (src/lib/ai/toolRouter.ts)
       - Strict Zod schema parameter validation
       - Tool allowlisting strictly mapped to user RBAC
       ↓
Layer 3: Evidence Citation Validation (src/lib/ai/evidenceValidator.ts)
       - AI claims must cite real evidence IDs
       - Hallucination score calculated: Score > 0.4 fails closed
       ↓
Layer 4: Deterministic Policy Gateway (src/lib/governance/decisionEngine.ts)
       - AI proposals must be submitted as structured proposals
       - Evaluated by Decision Engine -> Policy Engine -> Human Dual-Control Approval
```

---

## 3. Verification Evidence

Verified in automated test suite:
- `tests/phase-g-ai-layer.test.ts` (8/8 passing)
- `tests/security-injection.test.ts` (Prompt injection & SQL injection defense passing)
- `tests/ai-gateway-and-evaluation.test.ts` (6/6 passing)
