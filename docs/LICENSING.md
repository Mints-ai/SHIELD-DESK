# ShieldDesk — Cryptographic Licensing Specification

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA & Air-Gapped Deployments  
**Code Reference:** `src/lib/billing/licenses.ts`  
**Security Standard:** HMAC-SHA256 / Timing-Safe Signature Validation

---

## 1. Overview & Format

ShieldDesk implements a secure, portable, and cryptographically signed commercial licensing engine supporting both cloud-managed and air-gapped on-premises deployments.

A ShieldDesk Commercial License is represented as a compact base64url token with two segments separated by a period (`.`):
```
<encoded_payload>.<hmac_signature>
```

### Segment Details

1. **`encoded_payload`:** Base64url-encoded JSON representation of `LicensePayload`:
   ```json
   {
     "licenseId": "lic_9f8b4c72-3e2b-4567-b891-2d7c1a89b3f4",
     "tenantId": "tenant-enterprise-globex",
     "tier": "enterprise",
     "maxEndpoints": 1000,
     "maxUsers": 50,
     "features": [
       "sso_scim",
       "ai_gateway_byok",
       "custom_remediation_playbooks",
       "dedicated_vault_anchoring"
     ],
     "issuedAt": "2026-10-01T00:00:00.000Z",
     "expiresAt": "2027-10-01T00:00:00.000Z"
   }
   ```
2. **`hmac_signature`:** Base64url-encoded HMAC-SHA256 signature generated using `SHIELDDESK_LICENSE_SECRET`.

---

## 2. Verification Algorithm

License validation occurs synchronously on application startup and periodically in memory via `verifyCommercialLicense`:

```typescript
// 1. Structure Verification
const parts = rawLicense.split(".");
if (parts.length !== 2) throw new Error("Malformed license token");

// 2. Constant-Time Cryptographic Signature Check
const hmac = crypto.createHmac("sha256", secret).update(encodedPayload).digest();
const expectedSig = base64UrlEncode(hmac);
const isValid = crypto.timingSafeEqual(Buffer.from(receivedSig), Buffer.from(expectedSig));

// 3. Expiration Verification
if (Date.now() > new Date(payload.expiresAt).getTime()) {
  return { valid: false, reason: "License expired" };
}
```

### Security Defenses

- **Timing Attack Immunity:** Uses `crypto.timingSafeEqual` to eliminate timing side-channels during signature inspection.
- **Fail-Closed in Production:** In production mode (`NODE_ENV === "production"`), the server strictly throws if `SHIELDDESK_LICENSE_SECRET` is unset, preventing insecure default keys.
- **Tamper Evidence:** Modifying any payload field (such as `maxEndpoints` or `expiresAt`) invalidates the HMAC signature and immediately downgrades the tenant to unverified state.

---

## 3. Air-Gapped & Offline Deployments

For sovereign, defense, or air-gapped financial networks:
- Licenses do not require internet access or recurring phone-home callbacks to validate.
- License keys are supplied via environment variable `SHIELDDESK_LICENSE_KEY` or through the admin settings interface.
- 30-day grace periods trigger when nearing expiration, surfacing administrative alerts without terminating active security defenses.
