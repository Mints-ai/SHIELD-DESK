# ShieldDesk™ — Enterprise Entitlements & Feature Gating

**Document Version:** 2.0.0-commercial  
**Target Release:** ShieldDesk Commercial GA  
**Code References:**  
- Canonical Catalogue: `src/lib/billing/catalog.ts`
- Entitlement Service: `src/lib/billing/entitlements.ts`
- License Tokens: `src/lib/billing/licenses.ts`
- Subscription State: `src/lib/billing/plans.ts`

---

## 1. Authoritative Feature Entitlement Matrix

All feature gating resolves dynamically through `EntitlementService` (`src/lib/billing/entitlements.ts`), mapped directly to the canonical product catalogue:

| Feature Key | Description | Community Pilot | Professional SOC | Enterprise Defense |
| :--- | :--- | :---: | :---: | :---: |
| `telemetryIngest` | Real-time endpoint event stream ingestion | Yes | Yes | Yes |
| `realTimeDetection` | Sigma / YARA rule evaluation engine | Yes | Yes | Yes |
| `aiInvestigation` | Autonomous LLM root-cause synthesis | Community Model | Multi-Model (Gemini/Claude) | Multi-Model + Enterprise BYOK |
| `automatedRemediationTier1` | Autonomous low-risk containment (isolate host, kill process) | No | Yes | Yes |
| `governedRemediationTier2` | Single-operator human approval | Yes | Yes | Yes |
| `dualApprovalTier3` | Separation of duties / dual privileged approval | No | No | Yes |
| `siemConnectors` | Wazuh, Defender, Sentinel, Falcon ingest | No | 2 Connectors | Unlimited |
| `customRules` | Tenant-defined YARA & Sigma rules | 5 | 50 | Unlimited |
| `discordSlackAlerts` | Real-time incident notification webhooks | Yes | Yes | Yes |
| `endpointFleet` | Universal Go agent management & mTLS | Max 5 | Max 250 | Max 10,000 |
| `complianceVault` | Immutable SHA-256 Merkle evidence vault | 7 days | 90 days | 365+ days / External Anchor |

---

## 2. Server-Side Enforcement (Non-Negotiable Rule 4)

**Core Invariant:**
> *"Every request resolves User -> Org -> Subscription -> License -> Entitlement -> Resource."*

Hiding UI buttons is never treated as an authorization boundary. All sensitive operations invoke `EntitlementService.require`:

```typescript
await EntitlementService.require({
  tenantId: session.tenantId,
  feature: "automatedRemediationTier1",
  currentEndpointsCount: activeEndpoints,
  context: "Host isolation dispatch"
});
```

If the tenant lacks the required entitlement or has exceeded quotas:
1. Throws an `EntitlementViolationError` (HTTP 403 Forbidden).
2. Records an unauthorized attempt entry in the immutable hash-chain audit ledger.
3. The UI presents a modal allowing the tenant billing admin to upgrade via Stripe Checkout.

---

## 3. Quota Excess & Safety Telemetry Invariant

**Safety Invariant:**
Delinquency, grace periods, or quota excess MUST NEVER silently drop safety-critical telemetry, terminate existing agents, or delete customer evidence.
- **Active Endpoints:** Existing registered agents continue transmitting heartbeats and detections uninterrupted.
- **Excess Enrollments:** Attempts to enroll endpoints beyond plan caps (`maxEndpoints`) are safely rejected with `HTTP 402 / 403` until the tenant upgrades or deactivates unused seats.
- **Evidence Vault:** Expired subscriptions preserve existing evidence until retention thresholds expire.
