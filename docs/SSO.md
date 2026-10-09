# ShieldDesk — Enterprise Single Sign-On (SSO) Specification

**Document Version:** 1.0.0  
**Date:** 2026-10-09  
**Status:** `IMPLEMENTED` / `TESTED` (Logic & Endpoints) | `NOT_VERIFIED` (Live Customer Okta/Azure AD Setup)  
**Implementation:** [src/lib/auth/sso.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/auth/sso.ts), [src/app/api/auth/login/route.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/app/api/auth/login/route.ts)

---

## 1. Overview

ShieldDesk supports enterprise federation via OpenID Connect (OIDC) and SAML 2.0. Identity assertions are translated into cryptographically signed ShieldDesk session tokens (`shielddesk_session`).

---

## 2. Supported Identity Providers (IdP)

- **Microsoft Entra ID (Azure AD)**
- **Okta Enterprise**
- **Google Workspace (Cloud Identity)**
- **PingFederate / Generic SAML 2.0**

---

## 3. Claims Mapping Architecture

Incoming SAML assertions or OIDC ID tokens are mapped to ShieldDesk attributes:

| IdP Claim | ShieldDesk Attribute | Notes |
| :--- | :--- | :--- |
| `sub` / `NameID` | `user.id` | Immutable unique identifier |
| `email` | `user.email` | Primary authentication identifier |
| `groups` / `roles` | `user.role` | Mapped via tenant group rules to canonical 7-tier RBAC |
| `tenant_id` / `org` | `user.tenant_id` | Bound strictly to tenant domain matching |

### Security Invariants:
1. **No Client-Controlled Role Elevation:** Role assignments are evaluated server-side against tenant domain allowlists.
2. **Session Lifetimes:** SSO access tokens have a max lifetime of 1 hour with cryptographically verified refresh token rotation (`tests/enterprise-auth-identity-and-rbac.test.ts`).

---

## 4. Verification Evidence

Verified in `tests/enterprise-auth-identity-and-rbac.test.ts` (Subtest 3: *Enterprise SSO Configuration & Claims Mapping* passing).
