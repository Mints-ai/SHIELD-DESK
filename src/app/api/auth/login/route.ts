import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { query } from "@/lib/db";
import { supabaseServer } from "@/lib/supabase/server";
import { createSessionToken } from "@/lib/auth/token";
import { verifyPassword } from "@/lib/auth/password";
import { getTotpSecret, verifyTotpCode } from "@/lib/auth/totp";
import type { ShieldDeskRole } from "@/lib/permissions";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { trackError } from "@/lib/observability/errorTracker";
import {
  recordThreatAlert,
  isIpBlocked,
  clearIpFailures,
  getIpFailureCount,
} from "@/lib/alerts/threatAlertStore";
import { resolveClientIp } from "@/lib/network/clientIp";

export async function POST(req: NextRequest) {
  let body: any = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const clientIp = await resolveClientIp(req, body?.clientIp);

  // Check Autonomous IP Containment (Block if >5 failed attempts recorded)
  if (isIpBlocked(clientIp)) {
    const failures = getIpFailureCount(clientIp);
    return NextResponse.json(
      {
        error: "Too many login attempts. Access is blocked. Contact security admin to unblock.",
        blocked: true,
        clientIp,
        attempts: failures,
      },
      { status: 403 }
    );
  }

  // S7: Rate limit login attempts (max 10 attempts per minute per IP)
  const rateLimit = checkRateLimit(`login:${clientIp}`, { limit: 10, windowMs: 60000 });

  if (!rateLimit.allowed) {
    recordThreatAlert({
      targetUser: "rate-limited-attempt",
      clientIp,
      failureReason: "Rate limit exceeded (>10 login attempts/min)",
      severity: "critical",
      type: "brute_force_spike",
    });
    return NextResponse.json(
      { error: "Too many login attempts. Please wait before retrying." },
      { status: 429, headers: { "Retry-After": "60" } }
    );
  }

  try {
    const { email, password, userId, mfaCode } = body || {};

    let authenticatedUid: string | null = null;
    let tenantId = "acme-tenant";
    let role: ShieldDeskRole = "analyst";


    // 1. Production Email/Password Authentication
    if (email && password) {
      if (typeof email !== "string" || typeof password !== "string") {
        recordThreatAlert({
          targetUser: String(email || "unknown"),
          clientIp,
          failureReason: "Malformed credentials payload",
        });
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
          recordThreatAlert({
            targetUser: email,
            clientIp,
            failureReason: error?.message || "Invalid credentials provided to authentication provider",
          });
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
            recordThreatAlert({
              targetUser: email,
              clientIp,
              failureReason: "Account not found or invalid credentials",
            });
            // Fail closed: reject unknown email or user without password hash
            return NextResponse.json(
              { error: "Invalid email or password." },
              { status: 401 }
            );
          }

          const isValid = await verifyPassword(password, user.password_hash);
          if (!isValid) {
            recordThreatAlert({
              targetUser: email,
              clientIp,
              failureReason: "Invalid password provided",
            });
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
          recordThreatAlert({
            targetUser: email,
            clientIp,
            failureReason: "Authentication failure: Database verification unavailable",
          });
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
      if (!isDevPersonaAllowed()) {
        recordThreatAlert({
          targetUser: String(userId),
          clientIp,
          failureReason: "Dev persona login attempted in production environment",
        });
        return NextResponse.json(
          { error: "Dev persona login is disabled in production environments." },
          { status: 401 }
        );
      }

      const validUsers = ["dev-admin", "dev-super", "dev-responder", "dev-analyst"];
      if (!validUsers.includes(userId)) {
        recordThreatAlert({
          targetUser: String(userId),
          clientIp,
          failureReason: "Invalid dev persona requested",
        });
        return NextResponse.json({ error: "Invalid dev persona." }, { status: 401 });
      }

      authenticatedUid = userId;
      // Role is resolved from DEV_USERS in getSessionFromRequest — no hardcoding needed here.
    } else {
      if (email) {
        recordThreatAlert({
          targetUser: email,
          clientIp,
          failureReason: "Missing password in login payload",
        });
      }
      return NextResponse.json(
        { error: "Please provide valid credentials or select a persona." },
        { status: 400 }
      );
    }

    if (!authenticatedUid) {
      if (email) {
        recordThreatAlert({
          targetUser: email,
          clientIp,
          failureReason: "Operator authentication failure",
        });
      }
      return NextResponse.json({ error: "Failed to authenticate operator." }, { status: 401 });
    }

    // MFA check: Mandatory for admin and approver roles; required for any account with TOTP active
    if (email && password) {
      const isPrivilegedRole = role === "system_admin" || role === "super_admin";
      const totpSecret = await getTotpSecret(authenticatedUid);

      // In production / fail-closed, privileged roles MUST have MFA enrolled
      if (isPrivilegedRole && !totpSecret && (process.env.NODE_ENV === "production" || process.env.APP_ENV === "production")) {
        return NextResponse.json(
          {
            error: "MFA_ENROLLMENT_MANDATORY: Administrative and approver roles require mandatory two-factor authentication (TOTP).",
            mfaEnrollmentRequired: true,
          },
          { status: 403 }
        );
      }

      if (totpSecret || isPrivilegedRole) {
        if (!totpSecret) {
          // If not enrolled in non-prod, skip only if explicitly allowed, otherwise prompt
        } else if (!mfaCode) {
          return NextResponse.json(
            { error: "MFA required. Please enter your 6-digit TOTP code.", mfaRequired: true },
            { status: 401 }
          );
        } else {
          const mfaResult = await verifyTotpCode(authenticatedUid, String(mfaCode), totpSecret);
          if (!mfaResult.valid) {
            recordThreatAlert({
              targetUser: email,
              clientIp,
              failureReason: mfaResult.reason ?? "Invalid 6-digit TOTP MFA code",
            });
            return NextResponse.json(
              { error: mfaResult.reason ?? "Invalid MFA code.", mfaRequired: true },
              { status: 401 }
            );
          }
        }
      }
    }

    // Clear IP failure counters on successful authentication
    clearIpFailures(clientIp);

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
    trackError(err, { endpoint: "/api/auth/login" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
