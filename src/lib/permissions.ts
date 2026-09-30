import "server-only";

/**
 * ShieldDesk roles, per the development plan's RBAC table:
 *   System Admin — platform-wide privileges (including cross-tenant view)
 *   Super Admin  — company-level administration
 *   User         — permissions based on assigned role
 *
 * The four chat tools don't need per-record ownership checks the way an
 * HR tool would (there's no "my incident" concept in ShieldDesk — an
 * incident belongs to the tenant, not to one analyst). The permission
 * that actually matters here is whether a request can cross tenant
 * boundaries at all; every other check is tenant isolation, applied
 * uniformly to every query in lib/tools/shieldDeskChatTools.ts.
 */
export type ShieldDeskRole = "system_admin" | "super_admin" | "analyst" | "responder" | "viewer" | "auditor" | "user";

export type Permission =
  | "VIEW_CROSS_TENANT"
  | "MANAGE_USERS"
  | "incident.read"
  | "incident.investigate"
  | "cve.read"
  | "incident.mitigate"
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
    "approve.tier1",
    "approve.tier2",
    "approve.tier3",
  ],
  responder: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
    "approve.tier1",
    "approve.tier2",
  ],
  analyst: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    // analysts can flag low-risk Tier 1 actions for auto-containment
    "approve.tier1",
  ],
  viewer: [
    "incident.read",
    "cve.read",
    // Viewers have READ only — they cannot approve any action.
  ],
  auditor: [
    "incident.read",
    "cve.read",
    // Auditors have read-only access to audit logs, evidence packages, and compliance reports.
  ],
  user: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
    "approve.tier1",
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
};

export function canAccess(role: string, permission: Permission): boolean {
  const perms = ROLE_PERMISSIONS[role as ShieldDeskRole];
  return Boolean(perms?.includes(permission));
}

export const hasPermission = canAccess;

export function canExecuteTool(role: string, toolName: string): boolean {
  const requiredPermission = TOOL_PERMISSIONS[toolName];
  if (!requiredPermission) return false;
  return canAccess(role, requiredPermission);
}
