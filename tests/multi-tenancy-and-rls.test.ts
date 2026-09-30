import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  extractTenantContext,
  assertTenantAccess,
  enforceTenantBoundary,
  buildTenantSqlFilter,
  TenantResourceNotFoundError,
  TenantSpoofingError,
} from "../src/lib/tenancy";
import { withTenantContext, tenantQuery } from "../src/lib/db";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Phase 3: Multi-Tenancy Hardening & Row-Level Security (RLS)", async (t) => {
  const acmeAnalyst: SessionUser = {
    id: "usr-acme-analyst",
    tenant_id: "acme-tenant",
    role: "analyst",
  };

  const globexAnalyst: SessionUser = {
    id: "usr-globex-analyst",
    tenant_id: "globex-tenant",
    role: "analyst",
  };

  const platformAdmin: SessionUser = {
    id: "usr-platform-admin",
    tenant_id: "shielddesk-internal",
    role: "system_admin",
  };

  await t.test("Tenant Context Extraction: Derives context strictly from SessionUser", () => {
    const acmeContext = extractTenantContext(acmeAnalyst);
    assert.equal(acmeContext.tenantId, "acme-tenant");
    assert.equal(acmeContext.userId, "usr-acme-analyst");
    assert.equal(acmeContext.role, "analyst");
    assert.equal(acmeContext.canCrossTenant, false, "Analyst cannot cross tenant boundaries");

    const adminContext = extractTenantContext(platformAdmin);
    assert.equal(adminContext.tenantId, "shielddesk-internal");
    assert.equal(adminContext.canCrossTenant, true, "System admin can cross tenant boundaries");
  });

  await t.test("Anti-Enumeration Guard: Cross-tenant access throws 404 (NOT 403)", () => {
    // 1. Same tenant access succeeds
    assert.doesNotThrow(() => {
      assertTenantAccess(acmeAnalyst, "acme-tenant", "Incident INC-101");
    });

    // 2. Cross-tenant access by standard user throws TenantResourceNotFoundError (404)
    assert.throws(
      () => {
        assertTenantAccess(acmeAnalyst, "globex-tenant", "Incident INC-202");
      },
      (err: unknown) => {
        assert.ok(err instanceof TenantResourceNotFoundError);
        assert.equal(err.statusCode, 404, "Anti-enumeration requirement: Must return 404");
        assert.equal(err.code, "RESOURCE_NOT_FOUND");
        assert.match(err.message, /Incident INC-202 not found/);
        return true;
      }
    );

    // 3. Platform System Admin can cross tenant boundaries without error
    assert.doesNotThrow(() => {
      assertTenantAccess(platformAdmin, "globex-tenant", "Incident INC-202");
    });
  });

  await t.test("Tenant Spoofing Prevention: Rejects request body/query tenant tampering", () => {
    // 1. Untrusted tenant omitted: returns session tenant
    const resolvedTenant1 = enforceTenantBoundary(acmeAnalyst);
    assert.equal(resolvedTenant1, "acme-tenant");

    // 2. Untrusted tenant matches session: returns session tenant
    const resolvedTenant2 = enforceTenantBoundary(acmeAnalyst, "acme-tenant");
    assert.equal(resolvedTenant2, "acme-tenant");

    // 3. Untrusted tenant mismatch: throws TenantSpoofingError (P0 security alert)
    assert.throws(
      () => {
        enforceTenantBoundary(acmeAnalyst, "target-victim-tenant");
      },
      (err: unknown) => {
        assert.ok(err instanceof TenantSpoofingError);
        assert.equal(err.statusCode, 403);
        assert.equal(err.code, "TENANT_SPOOFING_DETECTED");
        assert.match(err.message, /cannot be overridden/);
        return true;
      }
    );

    // 4. Platform System Admin can override target tenant explicitly
    const adminTargetTenant = enforceTenantBoundary(platformAdmin, "globex-tenant");
    assert.equal(adminTargetTenant, "shielddesk-internal");
  });

  await t.test("SQL Tenant Scoping: Generates parameterized tenant filters", () => {
    // Standard user gets parameterized filter
    const analystFilter = buildTenantSqlFilter(acmeAnalyst, "inc", 2);
    assert.equal(analystFilter.sql, "inc.tenant_id = $2");
    assert.deepEqual(analystFilter.params, ["acme-tenant"]);

    // Default alias and start parameter index
    const defaultFilter = buildTenantSqlFilter(globexAnalyst);
    assert.equal(defaultFilter.sql, "tenant_id = $1");
    assert.deepEqual(defaultFilter.params, ["globex-tenant"]);

    // Platform admin gets no-op filter
    const adminFilter = buildTenantSqlFilter(platformAdmin, "inc", 1);
    assert.equal(adminFilter.sql, "1=1");
    assert.deepEqual(adminFilter.params, []);
  });

  await t.test("Database RLS Helpers: withTenantContext & tenantQuery are defined and callable", () => {
    assert.equal(typeof withTenantContext, "function");
    assert.equal(typeof tenantQuery, "function");
  });
});
