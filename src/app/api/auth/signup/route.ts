import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { query } from "@/lib/db";
import { supabaseServer } from "@/lib/supabase/server";
import { createSessionToken } from "@/lib/auth/token";
import { hashPassword } from "@/lib/auth/password";
import type { ShieldDeskRole } from "@/lib/permissions";

export async function POST(req: NextRequest) {
  const forwarded = req.headers.get("x-forwarded-for");
  const clientIp = forwarded ? forwarded.split(",")[0].trim() : "127.0.0.1";
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

    if (!email || !password || typeof email !== "string" || typeof password !== "string") {
      return NextResponse.json(
        { error: "Valid email and password are required." },
        { status: 400 }
      );
    }

    if (password.length < 8) {
      return NextResponse.json(
        { error: "Password must be at least 8 characters long." },
        { status: 400 }
      );
    }

    const assignedRole: ShieldDeskRole = role === "system_admin" ? "system_admin" : "user";
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
            organization_name: organizationName || "Default Organization",
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

    // 2. Persist to local PostgreSQL users table with secure password hash
    const hashedPassword = await hashPassword(password);
    try {
      await query(
        `INSERT INTO users (id, tenant_id, role, email, password_hash, created_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
        [createdUid, tenantId, assignedRole, email.toLowerCase().trim(), hashedPassword]
      );
    } catch (dbErr) {
      console.warn("[Signup] Local user persist warning:", dbErr);
    }

    // S2: Cryptographically sign session token
    const sessionToken = createSessionToken({
      uid: createdUid,
      tenantId,
      role: assignedRole,
    });

    const res = NextResponse.json({
      success: true,
      userId: createdUid,
      tenantId,
      token: sessionToken,
      message: "Registration successful. Welcome to ShieldDesk SOC.",
    });

    res.cookies.set("shielddesk_session", sessionToken, {
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
