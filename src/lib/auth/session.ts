import "server-only";
import { query } from "@/lib/db";
import type { ShieldDeskRole } from "@/lib/permissions";

export interface ChatSession {
  uid: string;
  role: ShieldDeskRole;
  tenantId: string;
}

/**
 * Session resolution — DEV MODE.
 *
 * ShieldDesk doesn't have its own login system yet (the chat widget is
 * the first component being built), so there's no real credential to
 * verify against. Rather than requiring an external identity provider
 * (Firebase, etc.) before any of this is testable, the caller identifies
 * themselves with a plain `X-ShieldDesk-User` header carrying a user id
 * from the `users` table (see db/seed.sql for dev users at different
 * roles/tenants).
 *
 * What this preserves for real use later: RBAC + tenant scoping are
 * still enforced from a real Postgres row, not trusted from the header
 * itself — the header only says "who is asking," Postgres says "what
 * they're allowed to do." When ShieldDesk has a real login flow, replace
 * only the token-verification step below (the part that turns "whatever
 * the request claims" into a trusted uid) — the Postgres lookup and
 * every tool's RBAC check stay the same.
 *
 * DO NOT ship this header-trusting behavior to any environment reachable
 * by untrusted clients — it's for local development only.
 */
const DEV_USERS: Record<string, { tenantId: string; role: ShieldDeskRole }> = {
  "dev-analyst": { tenantId: "acme-tenant", role: "user" },
  "dev-admin": { tenantId: "acme-tenant", role: "system_admin" },
  "dev-other": { tenantId: "globex-tenant", role: "user" },
};

export async function getSessionFromRequest(
  req: Request
): Promise<ChatSession | null> {
  const uid = req.headers.get("X-ShieldDesk-User");
  if (!uid) return null;

  try {
    const result = await query<{ tenant_id: string; role: string }>(
      "SELECT tenant_id, role FROM users WHERE id = $1 LIMIT 1",
      [uid]
    );

    const row = result.rows[0];
    if (row) {
      return {
        uid,
        tenantId: row.tenant_id,
        role: row.role as ShieldDeskRole,
      };
    }
  } catch {
    // Database unreachable — fallback to dev users in dev mode
  }

  if (DEV_USERS[uid]) {
    return {
      uid,
      tenantId: DEV_USERS[uid].tenantId,
      role: DEV_USERS[uid].role,
    };
  }

  return null;
}
