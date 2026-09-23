import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { query } from "@/lib/db";
import { supabaseServer } from "@/lib/supabase/server";

export async function POST(req: NextRequest) {
  const clientIp = req.headers.get("x-forwarded-for") || "127.0.0.1";
  const rateLimit = checkRateLimit(`signup:${clientIp}`, { limit: 5, windowMs: 60000 });

  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Too many registration attempts. Please wait a minute." },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();
    const { email, password, organizationName, role = "user" } = body;

    if (!email || !password) {
      return NextResponse.json(
        { error: "Email and password are required." },
        { status: 400 }
      );
    }

    const tenantId = organizationName
      ? organizationName.toLowerCase().replace(/[^a-z0-9]/g, "-") + "-tenant"
      : "custom-tenant";

    let createdUid: string = crypto.randomUUID();

    // 1. Supabase Auth Registration (if configured)
    if (supabaseServer) {
      const { data, error } = await supabaseServer.auth.signUp({
        email,
        password,
        options: {
          data: {
            tenant_id: tenantId,
            organization_name: organizationName || "Default Organization",
            role: role === "system_admin" ? "system_admin" : "user",
          },
        },
      });

      if (error) {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }

      if (data.user) {
        createdUid = data.user.id;
      }
    }

    // 2. Persist to local PostgreSQL users table if database is accessible
    try {
      await query(
        `INSERT INTO users (id, tenant_id, role, email, created_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (id) DO NOTHING`,
        [createdUid, tenantId, role, email]
      );
    } catch {
      // Local table update is best effort if db container is warming up
    }

    const res = NextResponse.json({
      success: true,
      userId: createdUid,
      tenantId,
      message: "Registration successful. Welcome to ShieldDesk SOC.",
    });

    res.cookies.set("shielddesk_session", createdUid, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 86400 * 7,
      path: "/",
    });

    return res;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error during registration";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
