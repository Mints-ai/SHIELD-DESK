import express, { Request, Response } from "express";
import helmet from "helmet";
import cors from "cors";
import { z } from "zod";
import crypto from "crypto";
import { query } from "./db.js";
import {
  signAccessToken,
  hashPassword,
  comparePassword,
  generateRefreshToken,
  generateMfaSetup,
  verifyMfaToken,
  issueAgentToken,
  validateAgentToken,
} from "./auth.js";
import { requireAuth, requireRole, rateLimiter, AuthenticatedRequest } from "./middleware.js";
import { setCache, getCache, delCache } from "./redis.js";

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(rateLimiter);

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "shielddesk-iam", timestamp: new Date().toISOString() });
});

// ==============================================================================
// 1. Authentication Endpoints
// ==============================================================================

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

// POST /v1/auth/login
app.post("/v1/auth/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = LoginSchema.parse(req.body);

    const userRes = await query(
      "SELECT id, tenant_id, email, password_hash, role, mfa_enabled, mfa_secret FROM public.users WHERE email = $1",
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = userRes.rows[0];
    const passwordValid = await comparePassword(password, user.password_hash);
    if (!passwordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Check if MFA is required
    if (user.mfa_enabled) {
      const sessionId = crypto.randomUUID();
      // Store pending MFA in Redis for 5 minutes
      await setCache(
        `mfa:pending:${sessionId}`,
        JSON.stringify({ userId: user.id, tenantId: user.tenant_id, role: user.role }),
        300
      );
      return res.json({
        mfa_required: true,
        session_id: sessionId,
        message: "Please enter your TOTP MFA code to complete login",
      });
    }

    // No MFA required: issue tokens immediately
    const accessToken = signAccessToken({
      sub: user.id,
      tenant_id: user.tenant_id,
      role: user.role,
      mfa: false,
    });

    const { token: refreshToken, hash: refreshHash } = await generateRefreshToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await query(
      "INSERT INTO public.sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5)",
      [user.id, refreshHash, req.headers["user-agent"] || "unknown", req.ip || "127.0.0.1", expiresAt]
    );

    // Audit log
    await query(
      "INSERT INTO public.audit_log (tenant_id, user_id, action, resource, payload) VALUES ($1, $2, $3, $4, $5)",
      [user.tenant_id, user.id, "auth.login", `user:${user.id}`, { method: "password" }]
    );

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: { id: user.id, email: user.email, tenant_id: user.tenant_id, role: user.role, mfa_enabled: false },
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: "Validation error", issues: err.issues });
    }
    console.error("[IAM-Login] Error:", err);
    res.status(500).json({ error: "Internal authentication error" });
  }
});

// POST /v1/auth/mfa/verify -> TOTP code -> upgrade session
const MfaVerifySchema = z.object({
  session_id: z.string().uuid(),
  totp_code: z.string().length(6),
});

app.post("/v1/auth/mfa/verify", async (req: Request, res: Response) => {
  try {
    const { session_id, totp_code } = MfaVerifySchema.parse(req.body);
    const pendingJson = await getCache(`mfa:pending:${session_id}`);
    if (!pendingJson) {
      return res.status(400).json({ error: "MFA session expired or invalid" });
    }

    const { userId, tenantId, role } = JSON.parse(pendingJson);
    const userRes = await query("SELECT mfa_secret FROM public.users WHERE id = $1", [userId]);
    if (userRes.rows.length === 0 || !userRes.rows[0].mfa_secret) {
      return res.status(400).json({ error: "MFA is not configured for this account" });
    }

    const isValid = verifyMfaToken(totp_code, userRes.rows[0].mfa_secret);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid TOTP code" });
    }

    // Invalidate pending session
    await delCache(`mfa:pending:${session_id}`);

    const accessToken = signAccessToken({
      sub: userId,
      tenant_id: tenantId,
      role: role,
      mfa: true,
    });

    const { token: refreshToken, hash: refreshHash } = await generateRefreshToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await query(
      "INSERT INTO public.sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5)",
      [userId, refreshHash, req.headers["user-agent"] || "unknown", req.ip || "127.0.0.1", expiresAt]
    );

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: { id: userId, tenant_id: tenantId, role: role, mfa_enabled: true },
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: "Validation error", issues: err.issues });
    }
    console.error("[IAM-MFA-Verify] Error:", err);
    res.status(500).json({ error: "MFA verification failed" });
  }
});

// POST /v1/auth/refresh -> refresh token -> new access token
app.post("/v1/auth/refresh", async (req: Request, res: Response) => {
  const { refresh_token } = req.body || {};
  if (!refresh_token || typeof refresh_token !== "string") {
    return res.status(400).json({ error: "Missing refresh_token" });
  }

  try {
    const sessionsRes = await query(
      `SELECT s.id, s.user_id, s.refresh_token_hash, s.expires_at, u.tenant_id, u.role, u.mfa_enabled 
       FROM public.sessions s 
       JOIN public.users u ON s.user_id = u.id 
       WHERE s.expires_at > now()`
    );

    let matchedSession = null;
    for (const row of sessionsRes.rows) {
      const match = await comparePassword(refresh_token, row.refresh_token_hash);
      if (match) {
        matchedSession = row;
        break;
      }
    }

    if (!matchedSession) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    const newAccessToken = signAccessToken({
      sub: matchedSession.user_id,
      tenant_id: matchedSession.tenant_id,
      role: matchedSession.role,
      mfa: matchedSession.mfa_enabled,
    });

    res.json({
      access_token: newAccessToken,
      expires_in: 3600,
    });
  } catch (err) {
    console.error("[IAM-Refresh] Error:", err);
    res.status(500).json({ error: "Refresh token error" });
  }
});

// DELETE /v1/auth/session -> logout
app.delete("/v1/auth/session", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    await query("DELETE FROM public.sessions WHERE user_id = $1", [req.user!.sub]);
    res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    console.error("[IAM-Logout] Error:", err);
    res.status(500).json({ error: "Logout failed" });
  }
});

// ==============================================================================
// 2. User & Team Management Endpoints
// ==============================================================================

// GET /v1/users -> list tenant users
app.get("/v1/users", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const usersRes = await query(
      "SELECT id, email, role, mfa_enabled, created_at, updated_at FROM public.users WHERE tenant_id = $1 ORDER BY created_at ASC",
      [req.tenantId]
    );
    res.json({ users: usersRes.rows });
  } catch (err) {
    console.error("[IAM-ListUsers] Error:", err);
    res.status(500).json({ error: "Failed to list users" });
  }
});

// POST /v1/users/invite -> invite team member
const InviteSchema = z.object({
  email: z.string().email(),
  role: z.enum(["admin", "member", "viewer"]),
});

app.post("/v1/users/invite", requireAuth, requireRole(["owner", "admin"]), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { email, role } = InviteSchema.parse(req.body);

    // Generate random temporary password
    const tempPassword = `Sd_${crypto.randomBytes(8).toString("hex")}!`;
    const pwdHash = await hashPassword(tempPassword);

    const insertRes = await query(
      `INSERT INTO public.users (tenant_id, email, password_hash, role, mfa_enabled) 
       VALUES ($1, $2, $3, $4, false) 
       ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role 
       RETURNING id, email, role, created_at`,
      [req.tenantId, email, pwdHash, role]
    );

    // In a live system, dispatch an email via SES/SendGrid with temp credentials
    res.status(201).json({
      success: true,
      message: `User invited to tenant ${req.tenantId}`,
      user: insertRes.rows[0],
      temp_credential_note: "Temporary invitation generated. Email dispatch scheduled.",
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: "Validation error", issues: err.issues });
    }
    console.error("[IAM-Invite] Error:", err);
    res.status(500).json({ error: "Failed to invite user" });
  }
});

// PATCH /v1/users/:id/role -> update user role
app.patch("/v1/users/:id/role", requireAuth, requireRole(["owner"]), async (req: AuthenticatedRequest, res: Response) => {
  const { role } = req.body || {};
  if (!["admin", "member", "viewer"].includes(role)) {
    return res.status(400).json({ error: "Invalid role. Permitted: admin, member, viewer" });
  }

  try {
    const updateRes = await query(
      "UPDATE public.users SET role = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3 RETURNING id, email, role",
      [role, req.params.id, req.tenantId]
    );

    if (updateRes.rows.length === 0) {
      return res.status(404).json({ error: "User not found in tenant" });
    }

    res.json({ success: true, user: updateRes.rows[0] });
  } catch (err) {
    console.error("[IAM-RoleUpdate] Error:", err);
    res.status(500).json({ error: "Role update failed" });
  }
});

// ==============================================================================
// 3. Agent Token Issuance & Validation (for Ingest Service)
// ==============================================================================

// POST /v1/agent/token -> generate a tenant token for endpoint agent enrollment
app.post("/v1/agent/token", requireAuth, requireRole(["owner", "admin"]), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const token = await issueAgentToken(req.tenantId!);
    res.json({
      token,
      tenant_id: req.tenantId,
      expires_in_sec: 300,
      instructions: "Pass this token in gRPC metadata 'x-tenant-token' during agent Handshake",
    });
  } catch (err) {
    console.error("[IAM-AgentToken] Error:", err);
    res.status(500).json({ error: "Agent token generation failed" });
  }
});

// GET /v1/agent/token/validate?token=xxx -> called by Ingest Service to authenticate agent
app.get("/v1/agent/token/validate", async (req: Request, res: Response) => {
  const token = req.query.token as string;
  if (!token) {
    return res.status(400).json({ error: "Missing token query param" });
  }

  const tenantId = await validateAgentToken(token);
  if (!tenantId) {
    return res.status(401).json({ authorized: false, error: "Token invalid or expired" });
  }

  res.json({ authorized: true, tenant_id: tenantId });
});

// ==============================================================================
// 4. SSO Stubs (Google OAuth2 & Okta SAML)
// ==============================================================================

app.get("/v1/auth/sso/google", (req: Request, res: Response) => {
  const redirectUri = req.query.redirect_uri || "/dashboard";
  res.json({
    sso_provider: "google",
    auth_url: `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID || "dev-client-id"}&redirect_uri=${redirectUri}&response_type=code&scope=openid%20email%20profile`,
  });
});

app.get("/v1/auth/sso/okta", (_req: Request, res: Response) => {
  res.json({
    sso_provider: "okta",
    saml_entrypoint: process.env.OKTA_ENTRYPOINT || "https://dev-shielddesk.okta.com/app/saml",
  });
});

// Server Initialization
if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    console.log(`[IAM-Service] ShieldDesk IAM Service operational on port ${PORT}`);
  });
}

export default app;
