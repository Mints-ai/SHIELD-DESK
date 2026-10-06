import "server-only";
import type { ShieldDeskRole } from "@/lib/permissions";

export interface ScimUserResource {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"];
  id: string;
  userName: string;
  name?: {
    formatted?: string;
    givenName?: string;
    familyName?: string;
  };
  emails: Array<{ value: string; primary?: boolean; type?: string }>;
  active: boolean;
  roles?: Array<{ value: ShieldDeskRole; primary?: boolean }>;
  meta: {
    resourceType: "User";
    created: string;
    lastModified: string;
    location: string;
  };
}

export interface ScimTenantDirectory {
  tenantId: string;
  users: Map<string, ScimUserResource>;
}

// In-memory SCIM directories partitioned by tenant
export const SCIM_DIRECTORIES: Map<string, ScimTenantDirectory> = new Map();

function getOrCreateDirectory(tenantId: string): ScimTenantDirectory {
  let dir = SCIM_DIRECTORIES.get(tenantId);
  if (!dir) {
    dir = { tenantId, users: new Map() };
    SCIM_DIRECTORIES.set(tenantId, dir);
  }
  return dir;
}

/**
 * Provisions a new user via SCIM 2.0.
 */
export function scimCreateUser(
  tenantId: string,
  params: {
    userName: string;
    email: string;
    displayName?: string;
    role?: ShieldDeskRole;
    active?: boolean;
  }
): ScimUserResource {
  const dir = getOrCreateDirectory(tenantId);
  const userId = `scim_${tenantId}_${Buffer.from(params.userName).toString("hex").substring(0, 12)}`;
  const now = new Date().toISOString();

  const userResource: ScimUserResource = {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: userId,
    userName: params.userName,
    name: {
      formatted: params.displayName || params.userName,
    },
    emails: [{ value: params.email, primary: true }],
    active: params.active !== false,
    roles: [{ value: params.role || "analyst", primary: true }],
    meta: {
      resourceType: "User",
      created: now,
      lastModified: now,
      location: `/api/scim/v2/${tenantId}/Users/${userId}`,
    },
  };

  dir.users.set(userId, userResource);
  return userResource;
}

/**
 * Updates an existing user via SCIM 2.0 (e.g. name, role, active status).
 */
export function scimUpdateUser(
  tenantId: string,
  userId: string,
  updates: {
    active?: boolean;
    role?: ShieldDeskRole;
    displayName?: string;
  }
): ScimUserResource | null {
  const dir = getOrCreateDirectory(tenantId);
  const user = dir.users.get(userId);
  if (!user) return null;

  if (typeof updates.active === "boolean") {
    user.active = updates.active;
  }
  if (updates.role) {
    user.roles = [{ value: updates.role, primary: true }];
  }
  if (updates.displayName) {
    user.name = { formatted: updates.displayName };
  }
  user.meta.lastModified = new Date().toISOString();

  return user;
}

/**
 * Deprovisions a user via SCIM 2.0 (sets active to false).
 */
export function scimDeprovisionUser(tenantId: string, userId: string): boolean {
  const updated = scimUpdateUser(tenantId, userId, { active: false });
  return updated !== null;
}

/**
 * Retrieves a user by SCIM ID.
 */
export function scimGetUser(tenantId: string, userId: string): ScimUserResource | null {
  const dir = getOrCreateDirectory(tenantId);
  return dir.users.get(userId) || null;
}
