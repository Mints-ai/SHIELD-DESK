import type { ShieldDeskRole } from "@/lib/permissions";

export interface TenantContext {
  tenantId: string;
  userId: string;
  role: ShieldDeskRole;
  canCrossTenant: boolean;
}

export class TenantResourceNotFoundError extends Error {
  public readonly code = "RESOURCE_NOT_FOUND";
  public readonly statusCode = 404;

  constructor(resourceName = "Resource") {
    // Master Prompt Section 15: Anti-enumeration returns 404, never 403
    super(`${resourceName} not found.`);
    this.name = "TenantResourceNotFoundError";
  }
}

export class TenantSpoofingError extends Error {
  public readonly code = "TENANT_SPOOFING_DETECTED";
  public readonly statusCode = 403;

  constructor(message = "P0 Security Incident: Attempted tenant parameter override rejected.") {
    super(message);
    this.name = "TenantSpoofingError";
  }
}
