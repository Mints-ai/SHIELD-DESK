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
export type ShieldDeskRole = "system_admin" | "super_admin" | "analyst" | "responder" | "viewer" | "user";

export type Permission =
  | "VIEW_CROSS_TENANT"
  | "MANAGE_USERS"
  | "incident.read"
  | "incident.investigate"
  | "cve.read"
  | "incident.mitigate";

const ROLE_PERMISSIONS: Record<ShieldDeskRole, Permission[]> = {
  system_admin: [
    "VIEW_CROSS_TENANT",
    "MANAGE_USERS",
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
  ],
  super_admin: [
    "MANAGE_USERS",
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
  ],
  responder: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
  ],
  analyst: [
    "incident.read",
    "incident.investigate",
    "cve.read",
  ],
  viewer: [
    "incident.read",
    "cve.read",
  ],
  user: [
    "incident.read",
    "incident.investigate",
    "cve.read",
    "incident.mitigate",
  ],
};

export const TOOL_PERMISSIONS: Record<string, Permission> = {
  getIncidents: "incident.read",
  investigateIncident: "incident.investigate",
  analyzeCve: "cve.read",
  generateMitigationPlan: "incident.mitigate",
};

export function canAccess(role: string, permission: Permission): boolean {
  const perms = ROLE_PERMISSIONS[role as ShieldDeskRole];
  return Boolean(perms?.includes(permission));
}

export function canExecuteTool(role: string, toolName: string): boolean {
  const requiredPermission = TOOL_PERMISSIONS[toolName];
  if (!requiredPermission) return false;
  return canAccess(role, requiredPermission);
}
