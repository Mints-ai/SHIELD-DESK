# ShieldDesk — SCIM 2.0 User Provisioning Specification

**Document Version:** 1.0.0  
**Date:** 2026-10-09  
**Status:** `IMPLEMENTED` / `TESTED` (API Routes & Schemas) | `NOT_VERIFIED` (Live Customer Tenant Sync)  
**Endpoints:** [src/app/api/scim/v2/Users/route.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/app/api/scim/v2/Users/route.ts), [src/app/api/scim/v2/Groups/route.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/app/api/scim/v2/Groups/route.ts)

---

## 1. Overview

ShieldDesk provides RFC 7643 & RFC 7644 compliant SCIM (System for Cross-domain Identity Management) endpoints for automated enterprise user provisioning, deprovisioning, and role synchronization from corporate directories (Okta, Entra ID).

---

## 2. Supported SCIM Operations

| Endpoint | Method | Operation | Behavior |
| :--- | :---: | :--- | :--- |
| `/api/scim/v2/Users` | `GET` | List Users | Returns paginated list of users filtered by tenant |
| `/api/scim/v2/Users` | `POST` | Create User | Provisions new user with tenant binding |
| `/api/scim/v2/Users/[id]` | `GET` | Get User | Retrieves user details by SCIM ID |
| `/api/scim/v2/Users/[id]` | `PATCH` / `PUT` | Update User | Updates name, email, or role; revokes sessions on disable (`active: false`) |
| `/api/scim/v2/Users/[id]` | `DELETE` | Deprovision User | Immediately revokes sessions and suspends account |
| `/api/scim/v2/Groups` | `GET` / `POST` | Group Management | Maps corporate groups to ShieldDesk RBAC roles |

---

## 3. Security Requirements

1. **Bearer Token Authentication:** Every SCIM request requires a high-entropy secret bearer token provisioned in the ShieldDesk tenant settings (`Authorization: Bearer <tenant_scim_token>`).
2. **Immediate Session Invalidation:** When a user is deprovisioned via SCIM (`active: false` or `DELETE`), any active session tokens (`shielddesk_session`) are instantly revoked.

---

## 4. Verification Evidence

Verified in `tests/enterprise-auth-identity-and-rbac.test.ts` (Subtest 4: *SCIM 2.0 User Provisioning & Deprovisioning* passing).
