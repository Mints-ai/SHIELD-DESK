# Phase 4 Changelog: Authentication, Enterprise Identity & RBAC Hardening

## Overview
Enforces the Master Prompt Section 16 & 17 requirements:
1. **Short-Lived Access Tokens & Refresh Token Family Rotation**:
   - Implemented short-lived 15-minute access tokens (`createAccessToken`) via HMAC-SHA256.
   - Implemented refresh tokens bound to token families (`createRefreshToken`, `verifyRefreshToken`).
   - Implemented automatic token rotation with anti-replay detection (`rotateRefreshToken`), where replaying an already-consumed refresh token immediately revokes the entire token family.
2. **Hashed API Key Lifecycle & Scopes (`src/lib/auth/apiKeys.ts`)**:
   - Standardized API key prefixing (`sdk_live_...`, `sdk_test_...`).
   - Implemented irreversible SHA-256 hashed storage (`hashApiKey`).
   - Added scope validation against required platform permissions (`verifyApiKey`).
   - Implemented immediate API key revocation (`revokeApiKey`).
3. **Enterprise Identity: SAML 2.0 & OIDC SSO Mapping (`src/lib/auth/sso.ts`)**:
   - Provider configurations supporting Okta, Azure AD / Microsoft Entra ID, Google Workspace, and generic SAML/OIDC.
   - Automatic tenant SSO resolution via tenant ID or email domain hint.
   - Claims processing and enterprise group-to-role mappings (`SecOps-Lead` $\rightarrow$ `super_admin`, `Compliance` $\rightarrow$ `auditor`).
4. **SCIM 2.0 Directory Synchronization (`src/lib/auth/scim.ts`)**:
   - SCIM 2.0 User resource representation (`urn:ietf:params:scim:schemas:core:2.0:User`).
   - Handlers for user provisioning, attribute updating, and deprovisioning (`active = false` upon employee offboarding).
5. **Canonical Roles & Permissions (`src/lib/permissions.ts`)**:
   - Added canonical `"auditor"` role with read-only access to incidents and CVEs, strictly blocked from approving remediation tiers or managing users.

## Key Changes
- `src/lib/auth/token.ts`: Added `createAccessToken`, `createRefreshToken`, `verifyRefreshToken`, `rotateRefreshToken`, and `revokeRefreshFamily`.
- `src/lib/auth/apiKeys.ts`: Created new API key manager with prefixing, SHA-256 hashing, scopes, and revocation.
- `src/lib/auth/sso.ts`: Created Enterprise SSO provider config and IdP claims processor.
- `src/lib/auth/scim.ts`: Created SCIM 2.0 directory provisioning engine.
- `src/lib/auth/index.ts`: Unified re-exports of all authentication, identity, and token modules.
- `src/lib/permissions.ts`: Added canonical `auditor` role and permissions.
- `tests/enterprise-auth-identity-and-rbac.test.ts`: Added dedicated unit test suite covering short-lived tokens, refresh rotation, replay detection, API key scopes, SSO claims, SCIM sync, and auditor RBAC.

## Verification
- All 22 test suites and 163 unit/integration tests passing (0 failures).
- TypeScript strict compilation passed cleanly (0 errors).
