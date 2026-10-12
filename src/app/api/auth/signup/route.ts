import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { query } from "@/lib/db";
import { supabaseServer } from "@/lib/supabase/server";
import { createSessionToken } from "@/lib/auth/token";
import { hashPassword } from "@/lib/auth/password";
import type { ShieldDeskRole } from "@/lib/permissions";
import { trackError } from "@/lib/observability/errorTracker";

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

    // S1: Security Invariant: Public registration must NEVER grant global system_admin.
    // The founding registrant creates an isolated organization tenant and is assigned
    // tenant-level 'super_admin' (organization owner & billing admin). Any user-supplied role is strictly ignored.
    const assignedRole: ShieldDeskRole = "super_admin";

    // S2: Server-authoritative unique tenant identifier.
    // Never allow a client to specify or hijack another organization's tenantId.
    const rawOrg = typeof organizationName === "string" ? organizationName.trim() : "";
    const cleanSlug = rawOrg
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 20) || "org";
    const uniqueSuffix = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
    const tenantId = `tenant_${cleanSlug}_${uniqueSuffix}`;

    let createdUid: string = crypto.randomUUID();

    // 1. Supabase Auth Registration (if configured)
    if (supabaseServer) {
      try {
        const { data, error } = await supabaseServer.auth.signUp({
          email,
          password,
          options: {
            data: {
              organization_name: rawOrg || "Default Organization",
              tenant_id: tenantId,
              role: assignedRole,
            },
          },
        });

        if (error) {
          console.warn("[Signup] Cloud auth warning (falling back to local user store):", error.message);
        } else if (data.user) {
          createdUid = data.user.id;
        }
      } catch (cloudErr: any) {
        console.warn("[Signup] Cloud auth connection exception:", cloudErr?.message || cloudErr);
      }
    }

    // 2. Persist to local PostgreSQL users table with secure password hash
    const isProd = process.env.NODE_ENV === "production" || process.env.APP_ENV === "production";
    try {
      const existingUser = await query<{ id: string }>(
        `SELECT id FROM users WHERE email = $1 LIMIT 1`,
        [email.toLowerCase().trim()]
      );
      if (existingUser.rows.length > 0) {
        return NextResponse.json(
          { error: "An account with this email address already exists. Please sign in instead." },
          { status: 409 }
        );
      }
    } catch {
      // Non-fatal if DB is in-memory or offline during dev unit tests
    }

    const hashedPassword = await hashPassword(password);
    try {
      await query(
        `INSERT INTO users (id, tenant_id, role, email, password_hash, created_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
        [createdUid, tenantId, assignedRole, email.toLowerCase().trim(), hashedPassword]
      );

      // Initialize default community tier subscription record
      await query(
        `INSERT INTO tenant_subscriptions (tenant_id, tier, status, current_period_end, updated_at)
         VALUES ($1, 'community', 'active', NOW() + INTERVAL '14 days', NOW())
         ON CONFLICT (tenant_id) DO NOTHING`,
        [tenantId]
      );
    } catch (dbErr) {
      if (isProd) {
        console.error("[Signup] CRITICAL_DATABASE_UNAVAILABLE: Failed to persist user account in production database:", dbErr);
        return NextResponse.json(
          { error: "Account registration failed: database service unavailable." },
          { status: 500 }
        );
      }
      console.warn("[Signup] Local user persist warning (dev/test mode):", dbErr);
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
      secure: process.env.NODE_ENV === "production" || process.env.APP_ENV === "production",
      sameSite: "lax",
      maxAge: 86400 * 7,
      path: "/",
    });

    return res;
  } catch (err: unknown) {
    trackError(err, { route: "POST /api/auth/signup" });
    const msg = err instanceof Error ? err.message : "Internal error during registration";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
