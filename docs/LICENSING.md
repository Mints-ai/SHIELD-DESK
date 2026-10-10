# ShieldDesk™ — Commercial Licensing Service Architecture

**Document Version:** 2.0.0-commercial  
**Target Release:** ShieldDesk Commercial GA & Air-Gapped Deployments  
**Code References:**  
- Core Cryptographic Licensing: `src/lib/billing/licenses.ts`
- Installation & Agent Activation: `src/lib/licensing/licenseActivation.ts`
- License APIs: `src/app/api/v1/licenses/*`
- Fleet mTLS & Certificates: `src/lib/fleet/certificates.ts`, `src/lib/fleet/mtlsGuard.ts`
- Command Signing & Key Ring: `src/lib/fleet/commandSigning.ts`

---

## 1. Cryptographic Principles & Threat Model

ShieldDesk enforces commercial compliance while upholding zero-trust operational safety:

1. **Zero Raw Secret Persistence:** Raw commercial license keys are NEVER stored in the database. Only an irreversible one-way keyed digest (`hashLicenseKey = HMAC-SHA256(pepper, rawLicense)`) and display fragments (`SD-ENT-****-B24F`) are persisted.
2. **Key Pepper vs. Signing Key Separation:** The lookup pepper (`SHIELDDESK_LICENSE_PEPPER`) is isolated from entitlement signing keys (`SHIELDDESK_LICENSE_SECRET`). Session secret fallback is prohibited.
3. **Asymmetric Signing for Customer-Hosted / Air-Gapped Nodes:** The licensing service retains the RSA-2048 private key. Customer-hosted agent binaries include only public verification keys, preventing reverse engineering of license-issuing capabilities.
4. **Hardware & Installation Binding:** Activations bind to installation UUIDs, device identities, and X.509 certificates.
5. **Transactional Seat Caps:** Concurrent activation attempts are enforced transactionally against `max_endpoints`.

---

## 2. License Key Architecture & Format

A ShieldDesk high-entropy commercial license key consists of two segments:
```
<encoded_payload>.<hmac_signature>
```

### 2.1 Payload Fields
```json
{
  "licenseId": "lic_7f8a9b2c3d4e5f60718293a4b5c6d7e8",
  "tenantId": "tenant-enterprise-globex",
  "tier": "enterprise",
  "maxEndpoints": 10000,
  "maxUsers": 100,
  "features": [
    "telemetryIngest",
    "realTimeDetection",
    "aiInvestigation",
    "automatedRemediationTier1",
    "governedRemediationTier2",
    "dualApprovalTier3",
    "siemConnectors",
    "customRules",
    "discordSlackAlerts",
    "endpointFleet",
    "complianceVault"
  ],
  "issuedAt": "2026-10-10T12:00:00.000Z",
  "expiresAt": "2027-10-10T12:00:00.000Z",
  "keyId": "sd-k1",
  "signingMode": "symmetric"
}
```

### 2.2 Peppered Database Lookup
```typescript
const pepper = process.env.SHIELDDESK_LICENSE_PEPPER;
const keyHash = crypto.createHmac("sha256", pepper).update(rawLicenseKey.trim()).digest("hex");
```
Queries verify:
```sql
SELECT * FROM product_licenses WHERE license_key_hash = $1 AND tenant_id = $2 AND status = 'active';
```

---

## 3. Asymmetric Entitlement Tokens (Offline & Air-Gapped)

Upon activation or refresh, the control plane returns an asymmetric entitlement token:
```
token = base64url(JSON({
  payload: {
    tenantId,
    installationId,
    tier,
    maxEndpoints,
    features,
    issuedAt,
    expiresAt,
    keyId: "sd-k1"
  },
  signature: RSA-SHA256(canonicalPayload, privateControlPlaneKey)
}))
```
Deployed software validates `signature` against the public key without requiring constant internet connectivity.

---

## 4. Activation, Refresh, Deactivation & Revocation Lifecycle

### 4.1 Activation (`POST /api/v1/licenses/activate`)
1. Agent presents `licenseKey`, `installationId`, `deviceIdentity`, and X.509 `certificatePem`.
2. Licensing service verifies device certificate authenticity via `MTLSGuard`.
3. Verifies `licenseKey` signature, expiration, and tenant binding.
4. Checks active seat count: `COUNT(active_activations) < max_endpoints`.
5. Inserts activation record in `license_activations` table.
6. Returns short-lived asymmetric signed entitlement token.

### 4.2 Periodic Refresh (`POST /api/v1/licenses/refresh`)
- Agents refresh tokens every 24 hours.
- If connectivity is lost, the agent operates under a configurable 14-day offline grace period.

### 4.3 Deactivation (`POST /api/v1/licenses/activations/:id/deactivate`)
- Authorized administrators can deactivate decommissioned or replaced installations, freeing seat slots immediately.

### 4.4 Administrative Revocation (`POST /api/v1/licenses/:id/revoke`)
- Strictly restricted to `system_admin` or `super_admin`.
- Transitions license status in `product_licenses` and `tenant_licenses` to `revoked`.
- Broadcasts revocation across the agent fleet, immediately rejecting further heartbeats and command dispatches.
- Written to immutable hash-chain audit ledger.
