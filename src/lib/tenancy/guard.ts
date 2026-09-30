import type { SessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { TenantContext, TenantResourceNotFoundError, TenantSpoofingError } from "./types";

/**
 * Extracts verified tenant context strictly from the authenticated SessionUser.
 * Never allows client request query/body to influence tenant identity.
 */
export function extractTenantContext(caller: SessionUser): TenantContext {
  if (!caller || !caller.tenant_id) {
    throw new Error("UNAUTHENTICATED_TENANT_CONTEXT: Session has no valid tenant binding.");
  }

  const canCrossTenant = canAccess(caller.role, "VIEW_CROSS_TENANT");

  return {
    tenantId: caller.tenant_id,
    userId: caller.id,
    role: caller.role,
    canCrossTenant,
  };
}

/**
 * Anti-Enumeration Guard:
 * Asserts that a caller has access to a specific tenant's resource.
 * If the resource belongs to another tenant and the caller lacks cross-tenant access,
 * this function throws TenantResourceNotFoundError (HTTP 404), NEVER 403 Forbidden.
 */
export function assertTenantAccess(
  caller: SessionUser,
  resourceTenantId: string,
  resourceName = "Resource"
): void {
  const context = extractTenantContext(caller);

  if (context.canCrossTenant) {
    return;
  }

  if (context.tenantId !== resourceTenantId) {
    // Master Prompt Section 15: Anti-enumeration returns 404, NOT 403
    throw new TenantResourceNotFoundError(resourceName);
  }
}

/**
 * Enforces that untrusted client input (from query params or request bodies)
 * cannot override or tamper with the session's authenticated tenant ID.
 * If client provides a tenantId different from the session tenantId,
 * it is treated as an active spoofing attempt and rejected.
 */
export function enforceTenantBoundary(
  caller: SessionUser,
  untrustedTenantId?: string | null
): string {
  const context = extractTenantContext(caller);

  if (untrustedTenantId && untrustedTenantId.trim() !== "") {
    if (untrustedTenantId !== context.tenantId && !context.canCrossTenant) {
      throw new TenantSpoofingError(
        `TENANT_SPOOFING_DETECTED: Session tenant '${context.tenantId}' cannot be overridden with '${untrustedTenantId}'.`
      );
    }
  }

  return context.tenantId;
}

/**
 * Builds SQL filter parameters for tenant scoping.
 * Returns SQL condition and parameter array.
 */
export function buildTenantSqlFilter(
  caller: SessionUser,
  tableAlias?: string,
  startParamIndex = 1
): { sql: string; params: unknown[] } {
  const context = extractTenantContext(caller);
  const column = tableAlias ? `${tableAlias}.tenant_id` : "tenant_id";

  if (context.canCrossTenant) {
    return { sql: "1=1", params: [] };
  }

  return {
    sql: `${column} = $${startParamIndex}`,
    params: [context.tenantId],
  };
}
