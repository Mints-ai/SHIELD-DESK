# Your Role & Permissions

Your administrator assigns you a role when your account is created. Higher roles inherit all permissions from roles below them.

## Role Table

| Role | Who it is for | Permissions |
|------|---------------|-------------|
| **Viewer** | Executives, auditors | Read-only: view incidents and CVE intelligence |
| **Analyst** | Junior SOC analysts | Investigate incidents, read CVEs, approve Tier 1 containment |
| **Responder** | Senior SOC engineers | All Analyst actions + Tier 2 (host isolation, patching) |
| **Super Admin** | SOC managers / team leads | Full team management, Tier 1-3 approvals (no cross-tenant) |
| **System Admin** | Platform administrators | All actions + cross-tenant visibility for multi-org oversight |

> If you see a **403 Forbidden** message, your role does not permit that action. Contact your Super Admin.

## Approval Tiers by Role

| Approval Tier | Who can approve |
|---------------|----------------|
| Tier 1 — Low-risk, reversible | Analyst, Responder, Super Admin, System Admin |
| Tier 2 — Host isolation, patching | Responder, Super Admin, System Admin |
| Tier 3 — Break-glass / destructive | Super Admin, System Admin only |
