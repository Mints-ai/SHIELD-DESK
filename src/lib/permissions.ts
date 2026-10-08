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
    // Responders can contain threats (Tier 1 & 2) but NOT break-glass (Tier 3).
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


export function canExecuteTool(role: string, toolName: string): boolean {
  const requiredPermission = TOOL_PERMISSIONS[toolName];
  if (!requiredPermission) return false;
  return canAccess(role, requiredPermission);
}
