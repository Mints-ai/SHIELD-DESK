import "server-only";
import { NextResponse } from "next/server";
import { query } from "@/lib/db";
import type { ShieldDeskRole } from "@/lib/permissions";
import { supabaseServer } from "@/lib/supabase/server";
import { verifySessionToken } from "@/lib/auth/token";
import { DEV_USERS } from "@/lib/constants/devUsers";

export interface ChatSession {
  uid: string;
  role: ShieldDeskRole;
  tenantId: string;
  email?: string;
}

export interface SessionUser {
  id: string;
  tenant_id: string;
  role: ShieldDeskRole;
  uid?: string;
  tenantId?: string;
}

/**
 * Session resolution supporting:
 * 1. Cryptographically signed HttpOnly session cookie (shielddesk_session).
 * 2. Enterprise Supabase Auth Bearer JWT tokens (verified with Supabase).
 * 3. Cryptographically signed Bearer session token.
 * 4. Dev mode fallback (DEV_USERS) strictly gated to non-production environments via X-ShieldDesk-User header.
 *
 * NOTE: Raw unsigned user IDs are strictly rejected to prevent session forgery (S2).
 */
export async function getSessionFromRequest(
  req: Request
): Promise<ChatSession | null> {
  let bearerToken: string | null = null;
  const authHeader = req.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    bearerToken = authHeader.substring(7).trim();
  }

  // 1. Check Cookie (shielddesk_session)
  let cookieToken: string | null = null;
  const cookieHeader = req.headers.get("cookie") || "";
  const match = cookieHeader.match(/shielddesk_session=([^;]+)/);
  if (match && match[1]) {
    cookieToken = decodeURIComponent(match[1]);
  }

  const token = bearerToken || cookieToken;

  // 2. Cryptographic Session Token Verification (ShieldDesk Signed Token)
  if (token) {
    const verifiedPayload = verifySessionToken(token);
    if (verifiedPayload) {
      return {
        uid: verifiedPayload.uid,
        tenantId: verifiedPayload.tenantId,
        role: verifiedPayload.role,
      };
    }

    // 3. Supabase JWT verification if token is a standard 3-part JWT
    if (supabaseServer && token.split(".").length === 3) {
      try {
        const { data, error } = await supabaseServer.auth.getUser(token);
        if (!error && data?.user) {
          // S5: Read role and tenant exclusively from server-set app_metadata,
          // never client-writable user_metadata.
          const tenantId =
            (data.user.app_metadata?.tenant_id as string) || "acme-tenant";
          const role =
            (data.user.app_metadata?.role as ShieldDeskRole) || "user";
          return {
            uid: data.user.id,
            tenantId,
            role,
            email: data.user.email,
          };
        } else if (error) {
          console.warn("[Auth] Supabase token verification failed:", error.message);
        }
      } catch (err: unknown) {
        console.error("[Auth] Exception during Supabase token verification:", err);
      }
    }
  }

  // 4. Check X-ShieldDesk-User header (Dev & Test mode ONLY)
  const isDevOrTest = process.env.NODE_ENV !== "production";
  if (isDevOrTest) {
    const devHeaderUid = req.headers.get("X-ShieldDesk-User");
    if (devHeaderUid && Object.prototype.hasOwnProperty.call(DEV_USERS, devHeaderUid)) {
      const devUser = DEV_USERS[devHeaderUid as keyof typeof DEV_USERS];
      if (devUser) {
        return {
          uid: devHeaderUid,
          tenantId: devUser.tenantId,
          role: devUser.role,
        };
      }
    }
  }

  // If no valid signed token or dev header matched, fail closed
  return null;
}

/**
 * Resolves current session user. Fails closed (returns null) if no valid
 * authenticated session is provided.
 */
export async function getSessionUser(req: Request): Promise<SessionUser | null> {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return null;
  }
  return {
    id: session.uid,
    uid: session.uid,
    role: session.role,
    tenant_id: session.tenantId,
    tenantId: session.tenantId,
  };
}

/**
 * Standard guard helper to enforce authentication on API routes.
 * Fails closed with 401 Unauthorized if request has no valid session.
 */
export async function requireTenantAuth(
  req: Request
): Promise<
  | { user: SessionUser; errorResponse?: never }
  | { user?: never; errorResponse: NextResponse }
> {
  const user = await getSessionUser(req);
  if (!user) {
    return {
      errorResponse: NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      ),
    };
  }
  return { user };
}
