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
    tenantId: "mints-global",
    tenantName: "MINTS GLOBAL",
    email: "admin@mintsglobal.ae",
    description: "Platform-wide administrator with cross-tenant visibility and Tier 3 approval authority",
  },
  "dev-super": {
    id: "dev-super",
    label: "Super Admin",
    role: "super_admin",
    tenantId: "mints-global",
    tenantName: "MINTS GLOBAL",
    email: "superadmin@mintsglobal.ae",
    description: "Company-level administrator — full approval authority within tenant",
  },
  "dev-responder": {
    id: "dev-responder",
    label: "Responder",
    role: "responder",
    tenantId: "mints-global",
    tenantName: "MINTS GLOBAL",
    email: "responder@mintsglobal.ae",
    description: "Incident Responder — can approve Tier 1 & Tier 2 containment actions",
  },
  "dev-analyst": {
    id: "dev-analyst",
    label: "Analyst",
    role: "analyst",
    tenantId: "mints-global",
    tenantName: "MINTS GLOBAL",
    email: "analyst@mintsglobal.ae",
    description: "SOC Analyst — investigate & draft plans, cannot approve actions",
  },
};

/**
 * Numeric tier levels corresponding to operator authority hierarchy:
 * 4: System Admin (Platform Admin / Cross-tenant / Tier 3 break-glass)
 * 3: Super Admin (Tenant Admin / Full tenant authority / Tier 3)
 * 2: Incident Responder (L3 Responder / Tier 1 & 2 containment)
 * 1: SOC Analyst (L1/L2 Investigation / Read-only / cannot assign tasks)
 */
export const ROLE_HIERARCHY_TIERS: Record<string, number> = {
  system_admin: 4,
  super_admin: 3,
  responder: 2,
  analyst: 1,
  user: 0,
  viewer: 0,
};

export function getRoleTier(role?: string | null): number {
  if (!role) return 0;
  return ROLE_HIERARCHY_TIERS[role] ?? 0;
}

export function getUserRole(userIdOrEmail?: string | null): ShieldDeskRole | null {
  if (!userIdOrEmail) return null;
  if (userIdOrEmail in DEV_USERS) {
    return DEV_USERS[userIdOrEmail as DevUserId].role;
  }
  const match = Object.values(DEV_USERS).find(
    (u) =>
      u.id === userIdOrEmail ||
      u.email.toLowerCase() === userIdOrEmail.toLowerCase() ||
      userIdOrEmail === `dev-${u.role}`
  );
  if (match) return match.role;

  if (userIdOrEmail in ROLE_HIERARCHY_TIERS) {
    return userIdOrEmail as ShieldDeskRole;
  }

  return null;
}

/**
 * Validates whether an assigner can assign a task to a target operator.
 * Lower tier employees cannot assign a task to higher tier employees.
 */
export function canAssignTaskToUser(
  assignerRole: string,
  assigneeRoleOrUserId: string | null | undefined
): boolean {
  if (!assigneeRoleOrUserId) return true; // Unassigned is always allowed
  const assignerTier = getRoleTier(assignerRole);
  const assigneeRole = getUserRole(assigneeRoleOrUserId) || assigneeRoleOrUserId;
  const assigneeTier = getRoleTier(assigneeRole);
  return assignerTier >= assigneeTier;
}

