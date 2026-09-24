import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { query } from "@/lib/db";
import { supabaseServer } from "@/lib/supabase/server";
import { createSessionToken } from "@/lib/auth/token";
import { verifyPassword } from "@/lib/auth/password";
import type { ShieldDeskRole } from "@/lib/permissions";

export async function POST(req: NextRequest) {
  // S7: Rate limit login attempts (max 10 attempts per minute per IP)
  const forwarded = req.headers.get("x-forwarded-for");
  const clientIp = forwarded ? forwarded.split(",")[0].trim() : "127.0.0.1";
  const rateLimit = checkRateLimit(`login:${clientIp}`, { limit: 10, windowMs: 60000 });

  if (!rateLimit.allowed) {
    return NextResponse.json(
      { error: "Too many login attempts. Please wait before retrying." },
      { status: 429, headers: { "Retry-After": "60" } }
    );
  }

  try {
    const body = await req.json();
    const { email, password, userId } = body;

    let authenticatedUid: string | null = null;
    let tenantId = "acme-tenant";
    let role: ShieldDeskRole = "user";

    // 1. Production Email/Password Authentication
    if (email && password) {
      if (typeof email !== "string" || typeof password !== "string") {
        return NextResponse.json(
          { error: "Email and password must be valid strings." },
          { status: 400 }
        );
      }

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

        authenticatedUid = data.user.id;
        // S5: Read tenant & role from server-controlled app_metadata, never client-controlled user_metadata
        tenantId = (data.user.app_metadata?.tenant_id as string) || "acme-tenant";
        role = (data.user.app_metadata?.role as ShieldDeskRole) || "user";
      } else {
        // S3: Secure local database authentication with Argon2/Scrypt hash verification
        try {
          const dbUser = await query<{
            id: string;
            tenant_id: string;
            role: string;
            password_hash: string | null;
          }>(
            "SELECT id, tenant_id, role, password_hash FROM users WHERE email = $1 LIMIT 1",
            [email.toLowerCase().trim()]
          );

          const user = dbUser.rows[0];
          if (!user || !user.password_hash) {
            // Fail closed: reject unknown email or user without password hash
            return NextResponse.json(
              { error: "Invalid email or password." },
              { status: 401 }
            );
          }

          const isValid = await verifyPassword(password, user.password_hash);
          if (!isValid) {
            return NextResponse.json(
              { error: "Invalid email or password." },
              { status: 401 }
            );
          }

          authenticatedUid = user.id;
          tenantId = user.tenant_id;
          role = user.role as ShieldDeskRole;
        } catch (dbErr) {
          console.error("[Auth] Database verification error:", dbErr);
          // Fail closed: do NOT fallback to demo user
          return NextResponse.json(
            { error: "Authentication service temporarily unavailable." },
            { status: 503 }
          );
        }
      }
    }
    // 2. Dev Persona Quick-Login (S1: Strictly blocked in production)
    else if (userId) {
      if (process.env.NODE_ENV === "production") {
        return NextResponse.json(
          { error: "Dev persona login is disabled in production environments." },
          { status: 401 }
        );
      }

      const validUsers = ["dev-analyst", "dev-admin", "dev-other"];
      if (!validUsers.includes(userId)) {
        return NextResponse.json({ error: "Invalid dev persona." }, { status: 401 });
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

    // S2: Cryptographically sign session token (HMAC-SHA256)
    const sessionToken = createSessionToken({
      uid: authenticatedUid,
      tenantId,
      role,
    });

    const res = NextResponse.json({
      success: true,
      userId: authenticatedUid,
      tenantId,
      role,
      token: sessionToken,
      message: "Authentication successful",
    });

    // Set secure signed session cookie
    res.cookies.set("shielddesk_session", sessionToken, {
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
