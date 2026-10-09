# ShieldDesk — Role-Based Access Control (RBAC) Specification

**Document Version:** 1.0.0  
**Date:** 2026-10-09  
**Status:** `IMPLEMENTED` / `TESTED`  
**Core Implementation:** [src/lib/permissions.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/permissions.ts)

---

## 1. Canonical Roles

ShieldDesk enforces 7 granular roles across all API routes, server actions, and chat tools:

| Role Identifier | Display Title | Scope | Key Capabilities |
| :--- | :--- | :--- | :--- |
| `system_admin` | System Administrator | Platform-wide | Cross-tenant view, manage all users, approve Tier 1-3 actions, kill-switches. |
| `super_admin` | Tenant Super Administrator | Tenant | Manage tenant users, approve Tier 1-3 break-glass actions. |
| `responder` | Security Responder | Tenant | Investigate incidents, generate plans, approve Tier 1 & Tier 2 actions. |
| `analyst` | Security Analyst | Tenant | Read incidents, investigate CVEs, propose plans, approve Tier 1 low-risk actions. |
| `auditor` | Compliance & Security Auditor | Tenant | Read-only access to audit ledgers, Merkle evidence vault, compliance reports. |
| `viewer` | Read-Only Viewer | Tenant | Read incidents and CVE findings. Cannot approve or trigger actions. |
| `user` | Standard User | Tenant | Baseline analyst privileges within designated tenant scope. |

---

## 2. Autonomy Tier Approval Gates

| Autonomy Tier | Risk Level | Description | Minimum Role Required | Permission |
| :---: | :---: | :--- | :--- | :--- |
| **Tier 0** | Zero | Informational / Observational queries | Any authenticated user | `incident.read` |
| **Tier 1** | Low | Low-risk reversible containment (e.g. block source IP) | `analyst`+ | `approve.tier1` |
| **Tier 2** | Medium/High | Host network isolation, process termination, patching | `responder`+ | `approve.tier2` |
| **Tier 3** | Critical | Host shutdown, reboot, emergency break-glass | `super_admin`+ | `approve.tier3` |

---

## 3. Separation of Duties

Enforced in [src/lib/governance/approvalTokens.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/governance/approvalTokens.ts):
- A user who requests an action token **CANNOT** self-approve their own token.
- Requester UID and Approver UID must be distinct:
  ```typescript
  if (token.requestedBy === session.uid) {
    throw new Error("FR-3: Separation of Duties — requester cannot self-approve their own action token");
  }
  ```

---

## 4. Verification Evidence

Verified in automated test suite:
- `tests/rbac.test.ts` (9/9 passing)
- `tests/approval-tokens.test.ts` (7/7 passing)
