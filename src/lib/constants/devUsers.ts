import type { ShieldDeskRole } from "@/lib/permissions";

export type DevUserId = "dev-analyst" | "dev-admin" | "dev-other";

export interface DevUserMetadata {
  id: DevUserId;
  label: string;
  role: ShieldDeskRole;
  tenantId: string;
  tenantName: string;
  email: string;
  description: string;
}

export const DEV_USERS: Record<DevUserId, DevUserMetadata> = {
  "dev-analyst": {
    id: "dev-analyst",
    label: "Analyst",
    role: "user",
    tenantId: "acme-tenant",
    tenantName: "Acme Corp",
    email: "analyst@acme.corp",
    description: "Standard SOC Analyst (Acme Corp)",
  },
  "dev-admin": {
    id: "dev-admin",
    label: "System Admin",
    role: "system_admin",
    tenantId: "acme-tenant",
    tenantName: "Acme Corp (Global Admin)",
    email: "admin@acme.corp",
    description: "Cross-Tenant Administrator (All Tenants)",
  },
  "dev-other": {
    id: "dev-other",
    label: "Globex Analyst",
    role: "user",
    tenantId: "globex-tenant",
    tenantName: "Globex Corp",
    email: "analyst@globex.corp",
    description: "External Tenant Analyst (Isolation Test)",
  },
};
