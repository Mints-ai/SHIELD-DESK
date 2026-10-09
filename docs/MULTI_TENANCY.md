# ShieldDesk — Multi-Tenancy Architecture & Security Isolation

**Document Version:** 1.0.0  
**Date:** 2026-10-09  
**Status:** `IMPLEMENTED` / `TESTED`  
**Core Principle:** Strict logical tenant isolation across all layers: Ingress, Application, Database, AI Context, and Endpoint Fleet.

---

## 1. Multi-Tenant Architecture Overview

ShieldDesk implements defense-in-depth tenant boundary enforcement at four distinct application layers:

```
[ Client Request ]
       ↓
Layer 1: Edge Proxy (src/proxy.ts)
       - Subdomain isolation (e.g. acme.shielddesk.com)
       - Cookie tenant-binding verification
       ↓
Layer 2: Control Plane Service Layer (src/lib/tenancy/)
       - enforceTenantBoundary() rejects client-supplied tenant spoofing
       - assertTenantAccess() enforces Anti-Enumeration (HTTP 404)
       ↓
Layer 3: Database Row-Level Security (PostgreSQL)
       - withTenantContext() executes:
           SET LOCAL app.current_tenant = $1;
           SET LOCAL app.user_role = $2;
       - PostgreSQL RLS policies enforce tenant boundaries at the database engine level
       ↓
Layer 4: Fleet & Endpoint Agent Broker (src/lib/broker/)
       - Ephemeral command tokens bind tenant_id, agent_id, and nonce
       - Endpoint mTLS certificate binds tenant_id
```

---

## 2. Anti-Enumeration Security Model

In multi-tenant SaaS environments, returning HTTP 403 Forbidden reveals that a resource exists under another tenant (BOLA / IDOR reconnaissance).

ShieldDesk enforces an **Anti-Enumeration 404** policy:
- If Tenant A attempts to access an incident, asset, command, or agent belonging to Tenant B, the API returns **HTTP 404 Not Found**.
- An audit event is logged internally (`TENANT_CROSS_ACCESS_ATTEMPT`) without disclosing resource existence to the caller.

---

## 3. Database Row-Level Security (RLS) Policy Specification

All 41 production tables enforce tenant partitioning via `tenant_id` columns and active PostgreSQL RLS:

```sql
-- Example RLS Policy for Incidents Table
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

CREATE POLICY incident_tenant_isolation ON incidents
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        OR current_setting('app.user_role', true) = 'super_admin'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
    );
```

### Context Activation Helper
Implemented in [src/lib/db/index.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/db/index.ts):
```typescript
export async function withTenantContext<T>(
  tenantId: string,
  role: string,
  fn: (clientQuery: ScopedQueryFn) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN;");
    await client.query("SELECT set_config('app.current_tenant', $1, true);", [tenantId]);
    await client.query("SELECT set_config('app.user_role', $2, true);", [role]);
    const result = await fn(...);
    await client.query("COMMIT;");
    return result;
  } catch (err) {
    await client.query("ROLLBACK;").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
```

---

## 4. Cross-Tenant Negative Attack Matrix & Evidence

| Attack Vector | Test File | Target Resource | Observed Behavior | Status |
| :--- | :--- | :--- | :--- | :---: |
| **IDOR Incident Probe** | `tests/rbac.test.ts` | `GET /api/incidents/INC-101` (Acme) by Globex user | Returns HTTP 404 Anti-enumeration | **PASS** |
| **Agent Enumeration** | `tests/fleet.test.ts` | `getEndpointAgent("FIN-WS-042", globexUser)` | Returns `null` -> HTTP 404 | **PASS** |
| **Task Board Cross-Query** | `tests/tasks-and-observability.test.ts` | `GET /api/tasks` with Globex session | Returns `{ tasks: [] }` scoped to Globex | **PASS** |
| **Approval Token Hijacking** | `tests/approval-tokens.test.ts` | Globex user approving Acme token | Throws `TOKEN_NOT_FOUND` (404) | **PASS** |
| **Tenant Parameter Tampering** | `tests/multi-tenancy-and-rls.test.ts` | `enforceTenantBoundary(acmeUser, "victim-tenant")` | Throws `TenantSpoofingError` (403) | **PASS** |
| **AI Context Cross-Contamination** | `tests/phase-g-ai-layer.test.ts` | Chat query requesting foreign tenant evidence | Rejects with citation mismatch score 0.0 | **PASS** |

---

## 5. Verification Commands

```powershell
npx tsx --test tests/multi-tenancy-and-rls.test.ts
npx tsx --test tests/rbac.test.ts
```
