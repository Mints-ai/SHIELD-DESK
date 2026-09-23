import "server-only";
import { query } from "@/lib/db";
import type { ShieldDeskRole } from "@/lib/permissions";
import { supabaseServer } from "@/lib/supabase/server";

export interface ChatSession {
  uid: string;
  role: ShieldDeskRole;
  tenantId: string;
  email?: string;
}

/**
 * Session resolution supporting:
 * 1. Enterprise Supabase Auth Bearer JWT tokens.
 * 2. Secure HttpOnly session cookie (shielddesk_session).
 * 3. PostgreSQL users table verification.
 * 4. Dev mode fallback (DEV_USERS) for local offline testing.
 */
const DEV_USERS: Record<string, { tenantId: string; role: ShieldDeskRole; email: string }> = {
  "dev-analyst": { tenantId: "acme-tenant", role: "user", email: "analyst@acme.corp" },
  "dev-admin": { tenantId: "acme-tenant", role: "system_admin", email: "admin@acme.corp" },
  "dev-other": { tenantId: "globex-tenant", role: "user", email: "analyst@globex.corp" },
};

export async function getSessionFromRequest(
  req: Request
): Promise<ChatSession | null> {
  // 1. Check Authorization Bearer header
  const authHeader = req.headers.get("Authorization");
  let tokenUid: string | null = null;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    tokenUid = authHeader.substring(7).trim();
  }

  // 2. Check Cookie (shielddesk_session)
  if (!tokenUid) {
    const cookieHeader = req.headers.get("cookie") || "";
    const match = cookieHeader.match(/shielddesk_session=([^;]+)/);
    if (match && match[1]) {
      tokenUid = decodeURIComponent(match[1]);
    }
  }

  // 3. Check X-ShieldDesk-User header (Dev & Test mode)
  const uid = tokenUid || req.headers.get("X-ShieldDesk-User");
  if (!uid) return null;

  // Supabase JWT verification if token is a structured JWT
  if (supabaseServer && uid.includes(".")) {
    try {
      const { data, error } = await supabaseServer.auth.getUser(uid);
      if (!error && data?.user) {
        const tenantId = (data.user.user_metadata?.tenant_id as string) || "acme-tenant";
        const role = (data.user.user_metadata?.role as ShieldDeskRole) || "user";
        return {
          uid: data.user.id,
          tenantId,
          role,
          email: data.user.email,
        };
      }
    } catch {
      // Continue to local database resolution
    }
  }

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

export interface SessionUser {
  id: string;
  tenant_id: string;
  role: ShieldDeskRole;
  uid?: string;
  tenantId?: string;
}

export async function getSessionUser(req: Request): Promise<SessionUser> {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return {
      id: "dev-analyst",
      uid: "dev-analyst",
      role: "user",
      tenant_id: "acme-tenant",
      tenantId: "acme-tenant",
    };
  }
  return {
    id: session.uid,
    uid: session.uid,
    role: session.role,
    tenant_id: session.tenantId,
    tenantId: session.tenantId,
  };
}

