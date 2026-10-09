# ShieldDesk — Enterprise Entitlements & Feature Gating

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Code Reference:** `src/lib/billing/entitlements.ts`, `src/lib/billing/plans.ts`  
**Core Model:** Role & License-Bound Feature Flags, Quota Enforcement & Offline Attestation

---

## 1. Overview & Feature Matrix

ShieldDesk governs capabilities dynamically using `EntitlementService` (`src/lib/billing/entitlements.ts`). Each tenant subscription maps to a granular entitlement bundle determining enabled features, agent quotas, and autonomy permissions.

### Canonical Feature Keys

| Feature Key | Description | Starter | Professional | Enterprise |
| :--- | :--- | :---: | :---: | :---: |
| `telemetryIngest` | Real-time agent event stream ingestion | Yes | Yes | Yes |
| `realTimeDetection` | Sigma / YARA rule evaluation engine | Yes | Yes | Yes |
| `aiInvestigation` | Automated LLM root-cause synthesis | Basic | Full | BYOK + Multi-Model |
| `automatedRemediationTier1` | Tier 1 autonomous low-risk fixes | No | Yes | Yes |
| `governedRemediationTier2` | Single-operator human approval | Yes | Yes | Yes |
| `dualApprovalTier3` | Separation of duties / dual approval | No | No | Yes |
| `siemConnectors` | Wazuh, Defender, Sentinel, Falcon integration | No | 2 Connectors | Unlimited |
| `customRules` | Tenant-defined detection & correlation rules | 5 | 50 | Unlimited |
| `discordSlackAlerts` | Real-time webhook notifications | Yes | Yes | Yes |
| `endpointFleet` | Universal Go agent management & mTLS | Max 25 | Max 250 | Unlimited |
| `complianceVault` | Immutable SHA-256 Merkle audit ledger | 14 days | 90 days | 365+ days / External Anchor |

---

## 2. Enforcement & Error Handling

Feature access is verified programmatically before executing sensitive operations:

```typescript
// Gate check example in route or business logic:
await EntitlementService.assertFeatureEnabled(tenantId, "dualApprovalTier3");
```

If a tenant lacks the required entitlement:
1. Throws an `EntitlementViolationError` (HTTP 403 Forbidden).
2. Emits audit telemetry to `src/lib/fleet/fleet.ts` hash chain recording the unauthorized attempt.
3. The UI gracefully surfaces an upgrade modal with direct Stripe checkout integration.

---

## 3. Offline Entitlement Caching

For air-gapped or hybrid deployments, the control plane issues a cryptographically signed `SignedOfflineCache`:
- Signed using the control plane private key (`signControlPlaneData`).
- Contains `allowedFeatures`, `maxEndpoints`, `expiresAt`, and `graceUntil`.
- The agent or on-prem deployment verifies the offline cache token locally without cloud connectivity.
- Enforces an automated 14-day grace period upon license expiry before restricting administrative operations.
