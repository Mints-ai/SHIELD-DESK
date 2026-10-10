import type { ShieldDeskRole } from "@/lib/permissions";

export type DevUserId = "dev-admin" | "dev-super" | "dev-responder" | "dev-analyst";


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
  "dev-admin": {
    id: "dev-admin",
    label: "System Admin",
    role: "system_admin",
    tenantId: "acme-tenant",
    tenantName: "MINTS GLOBAL",
    email: "admin@mintsglobal.ae",
    description: "Platform-wide administrator with cross-tenant visibility and Tier 3 approval authority",
  },
  "dev-super": {
    id: "dev-super",
    label: "Super Admin",
    role: "super_admin",
    tenantId: "acme-tenant",
    tenantName: "MINTS GLOBAL",
    email: "superadmin@mintsglobal.ae",
    description: "Company-level administrator — full approval authority within tenant",
  },
  "dev-responder": {
    id: "dev-responder",
    label: "Responder",
    role: "responder",
    tenantId: "acme-tenant",
    tenantName: "MINTS GLOBAL",
    email: "responder@mintsglobal.ae",
    description: "Incident Responder — can approve Tier 1 & Tier 2 containment actions",
  },
  "dev-analyst": {
    id: "dev-analyst",
    label: "Analyst",
    role: "analyst",
    tenantId: "acme-tenant",
    tenantName: "MINTS GLOBAL",
    email: "analyst@mintsglobal.ae",
    description: "SOC Analyst — investigate & draft plans, cannot approve actions",
  },
};
