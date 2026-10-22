import "server-only";

/**
 * ShieldDesk RBAC — 4-role model:
 *   system_admin — platform-wide privileges, cross-tenant visibility, all approvals
 *   super_admin  — company-level admin, all approvals within tenant
 *   responder    — incident response, Tier 1 & 2 approvals, task assignment
 *   analyst      — read-only investigation, cannot approve or assign tasks
 *
 * Tenant isolation is enforced uniformly on every DB query in
 * lib/tools/shieldDeskChatTools.ts. The permission that gates cross-tenant
 * access is VIEW_CROSS_TENANT, held only by system_admin.
 */
export type ShieldDeskRole = "system_admin" | "super_admin" | "responder" | "analyst";


export type Permission =
  | "VIEW_CROSS_TENANT"
  | "MANAGE_USERS"
  | "integrations.keys.manage"
  | "incident.read"
  | "incident.investigate"
  | "cve.read"
  | "incident.mitigate"
  | "task.assign"     // create / assign remediation tasks
  // Approval tier gates — additive. Each role can approve up to its highest tier.
  | "approve.tier1"  // low-risk reversible (Tier 1)
  | "approve.tier2"  // host isolation / patching (Tier 2) — requires responder+
  | "approve.tier3"; // break-glass / destructive (Tier 3) — requires super_admin+

const ROLE_PERMISSIONS: Record<ShieldDeskRole, Permission[]> = {
  system_admin: [
    "VIEW_CROSS_TENANT",
    "MANAGE_USERS",
    "integrations.keys.manage",
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
    "task.assign",
    "approve.tier1",
    "approve.tier2",
    "approve.tier3",
  ],
  super_admin: [
    "MANAGE_USERS",
    "integrations.keys.manage",
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
    "task.assign",
    "approve.tier1",
    "approve.tier2",
    "approve.tier3",
  ],
  responder: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
    "task.assign",
    "approve.tier1",
    "approve.tier2",
    // Responders can contain threats (Tier 1 & 2) but CANNOT approve break-glass (Tier 3).
  ],
  analyst: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    // Analysts are read-only: they can view incidents/CVEs and investigate,
    // but CANNOT mitigate, assign tasks, or approve any action.
  ],
};


/** Maps an AutonomyTier string to the Permission required to approve it. */
export const TIER_APPROVE_PERMISSIONS: Record<string, Permission> = {
  "Tier 1": "approve.tier1",
  "Tier 2": "approve.tier2",
  "Tier 3": "approve.tier3",
};

export const TOOL_PERMISSIONS: Record<string, Permission> = {
  getIncidents: "incident.read",
  investigateIncident: "incident.investigate",
  analyzeCve: "cve.read",
  generateMitigationPlan: "incident.mitigate",
  simulateBlastRadius: "cve.read",
  triggerTrivyScan: "cve.read",
};

export function canAccess(role: string, permission: Permission): boolean {
  const perms = ROLE_PERMISSIONS[role as ShieldDeskRole];
  return Boolean(perms?.includes(permission));
}

export const hasPermission = canAccess;

/**
 * Returns true if the role is permitted to create / assign remediation tasks.
 * Permitted roles: system_admin, super_admin, responder.
 * Analysts are read-only and cannot assign tasks.
 */
export function canAssignTask(role: string, tenantId: string): boolean {
  return canAccess(role as ShieldDeskRole, "task.assign");
}

/**
 * Returns true if the role is permitted to configure, test, or remove third-party integration keys (Shodan, HIBP).
 * Permitted roles: system_admin, super_admin.
 */
export function canManageIntegrationKeys(role?: string | null): boolean {
  if (!role) return false;
  return canAccess(role, "integrations.keys.manage");
}


export function canExecuteTool(role: string, toolName: string): boolean {
  const requiredPermission = TOOL_PERMISSIONS[toolName];
  if (!requiredPermission) return false;
  return canAccess(role, requiredPermission);
}

/**
 * Numeric tier levels corresponding to operator authority hierarchy:
 * 4: system_admin (Platform Admin / Cross-tenant / Tier 3 break-glass)
 * 3: super_admin (Tenant Admin / Full tenant authority / Tier 3)
 * 2: responder (L3 Responder / Tier 1 & 2 containment)
 * 1: analyst (L1/L2 Investigation / Read-only / cannot assign tasks)
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

/**
 * Enforces hierarchy rule: Lower tier employees cannot assign a task to higher tier employees.
 * Assigning to equal or lower tier is permitted.
 */
export function canAssignTaskToAssignee(assignerRole: string, assigneeRole: string): boolean {
  return getRoleTier(assignerRole) >= getRoleTier(assigneeRole);
}

