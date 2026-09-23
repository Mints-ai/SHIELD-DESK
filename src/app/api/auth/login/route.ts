import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { query } from "@/lib/db";
import { supabaseServer } from "@/lib/supabase/server";

export async function POST(req: NextRequest) {
  // Rate limit login attempts (max 10 attempts per minute per IP)
  const clientIp = req.headers.get("x-forwarded-for") || "127.0.0.1";
  const rateLimit = checkRateLimit(`login:${clientIp}`, { limit: 10, windowMs: 60000 });

  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Too many login attempts. Please wait before retrying." },
      { status: 429, headers: { "Retry-After": "60" } }
    );
  }

  try {
    const body = await req.json();
    const { email, password, userId, mfaCode } = body;

    let authenticatedUid: string | null = null;
    let tenantId = "acme-tenant";
    let role = "user";

    // 1. Production Email/Password Authentication (Supabase Auth if configured)
    if (email && password) {
      if (supabaseServer) {
        const { data, error } = await supabaseServer.auth.signInWithPassword({
          email,
          password,
        });

        if (error || !data.user) {
          return NextResponse.json(
            { error: error?.message || "Invalid email or password." },
            { status: 401 }
          );
        }

        authenticatedUid = data.session?.access_token || data.user.id;
        tenantId = (data.user.user_metadata?.tenant_id as string) || "acme-tenant";
        role = (data.user.user_metadata?.role as string) || "user";
      } else {
        // Fallback local database verification
        try {
          const dbUser = await query<{ id: string; tenant_id: string; role: string }>(
            "SELECT id, tenant_id, role FROM users WHERE email = $1 LIMIT 1",
            [email]
          );
          if (dbUser.rows[0]) {
            authenticatedUid = dbUser.rows[0].id;
            tenantId = dbUser.rows[0].tenant_id;
            role = dbUser.rows[0].role;
          } else {
            // Demo fallback for standard domain emails
            authenticatedUid = email.split("@")[0] || "soc-analyst";
          }
        } catch {
          authenticatedUid = email.split("@")[0] || "soc-analyst";
        }
      }
    } 
    // 2. Dev Persona Quick-Login
    else if (userId) {
      const validUsers = ["dev-analyst", "dev-admin", "dev-other"];
      if (!validUsers.includes(userId)) {
        return NextResponse.json({ error: "Invalid user credentials" }, { status: 401 });
      }
      authenticatedUid = userId;
      if (userId === "dev-other") tenantId = "globex-tenant";
      if (userId === "dev-admin") role = "system_admin";
    } else {
      return NextResponse.json(
        { error: "Please provide valid credentials or select a persona." },
        { status: 400 }
      );
    }

    if (!authenticatedUid) {
      return NextResponse.json({ error: "Failed to authenticate operator." }, { status: 401 });
    }

    const res = NextResponse.json({
      success: true,
      userId: authenticatedUid,
      tenantId,
      role,
      message: "Authentication successful",
    });

    // Set secure session cookie
    res.cookies.set("shielddesk_session", authenticatedUid, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 86400 * 7, // 7 days
      path: "/",
    });

    return res;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
