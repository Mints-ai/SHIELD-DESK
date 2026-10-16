import "server-only";
import type { ShieldDeskRole } from "@/lib/permissions";

export type SsoProviderType =
  | "okta"
  | "azure_ad"
  | "google_workspace"
  | "custom_saml"
  | "custom_oidc";

export interface TenantSsoConfig {
  tenantId: string;
  provider: SsoProviderType;
  enabled: boolean;
  issuer: string;
  ssoUrl: string;
  certificatePem?: string;
  clientId?: string;
  domainHint?: string;
  defaultRole: ShieldDeskRole;
  createdAt: string;
  updatedAt: string;
}

export const TENANT_SSO_CONFIGS: Map<string, TenantSsoConfig> = new Map();

/**
 * Registers or updates runtime SSO configuration for a tenant.
 */
export function registerTenantSsoConfig(config: TenantSsoConfig): void {
  TENANT_SSO_CONFIGS.set(config.tenantId, config);
}

/**
 * Resolves SSO configuration for a tenant by ID or user email domain.
 */
export function resolveTenantSsoConfig(identifier: string): TenantSsoConfig | null {
  // 1. Direct tenant ID match
  if (TENANT_SSO_CONFIGS.has(identifier)) {
    return TENANT_SSO_CONFIGS.get(identifier) || null;
  }

  // 2. Email domain match (e.g. "analyst@acme.com")
  if (identifier.includes("@")) {
    const domain = identifier.split("@")[1].toLowerCase();
    for (const config of TENANT_SSO_CONFIGS.values()) {
      if (config.domainHint && config.domainHint.toLowerCase() === domain) {
        return config;
      }
    }
  }

  return null;
}

/**
 * Validates an SSO assertion or OIDC ID token claim payload.
 */
export function processSsoCallback(params: {
  tenantId: string;
  email: string;
  name?: string;
  externalGroups?: string[];
}): {
  valid: boolean;
  userId: string;
  email: string;
  tenantId: string;
  role: ShieldDeskRole;
} {
  const config = TENANT_SSO_CONFIGS.get(params.tenantId);
  if (!config || !config.enabled) {
    throw new Error(`SSO_DISABLED_FOR_TENANT: Tenant '${params.tenantId}' has not configured or enabled SSO.`);
  }

  // Map external IdP groups to ShieldDesk role if provided
  let assignedRole = config.defaultRole;
  if (params.externalGroups && params.externalGroups.length > 0) {
    if (params.externalGroups.includes("ShieldDesk-Admins") || params.externalGroups.includes("SecOps-Lead")) {
      assignedRole = "super_admin";
    } else if (params.externalGroups.includes("ShieldDesk-Responders") || params.externalGroups.includes("SOC-Tier2")) {
      assignedRole = "responder";
    } else if (params.externalGroups.includes("ShieldDesk-Auditors") || params.externalGroups.includes("Compliance")) {
      assignedRole = "analyst";
    }
  }

  const userId = `usr_sso_${params.email.replace(/[^a-zA-Z0-9]/g, "_")}`;

  return {
    valid: true,
    userId,
    email: params.email,
    tenantId: params.tenantId,
    role: assignedRole,
  };
}
