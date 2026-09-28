import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { generateTotpSetup, commitTotpSecret, verifyTotpCode } from "@/lib/auth/totp";
import { query } from "@/lib/db";

/**
 * GET /api/auth/mfa/setup
 * Generates a TOTP secret + QR code for the authenticated user.
 * Returns the qrDataUrl (base64 PNG) and the raw otpauthUrl.
 * The secret is stored as `totp_pending_secret` until confirmed via POST.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Fetch email for the otpauth label
  let email = session.uid;
  try {
    const res = await query<{ email: string }>(
      `SELECT email FROM users WHERE id = $1 LIMIT 1`,
      [session.uid]
    );
    if (res.rows[0]?.email) email = res.rows[0].email;
  } catch {
    // non-fatal — use uid as label fallback
  }

  const setup = await generateTotpSetup(session.uid, email);

  return NextResponse.json({
    otpauthUrl: setup.otpauthUrl,
    qrDataUrl: setup.qrDataUrl,
    message: "Scan the QR code with your authenticator app, then confirm with a valid 6-digit code.",
  });
}

/**
 * POST /api/auth/mfa/setup
 * Body: { code: "123456" }
 * Verifies the code against the pending secret and promotes it to active if valid.
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => ({}));
  const { code } = body;

  // Fetch the pending secret
  let pendingSecret: string | null = null;
  try {
    const res = await query<{ totp_pending_secret: string | null }>(
      `SELECT totp_pending_secret FROM users WHERE id = $1 LIMIT 1`,
      [session.uid]
    );
    pendingSecret = res.rows[0]?.totp_pending_secret ?? null;
  } catch {
    return NextResponse.json(
      { error: "Could not retrieve pending TOTP secret. Please restart enrollment." },
      { status: 500 }
    );
  }

  if (!pendingSecret) {
    return NextResponse.json(
      { error: "No pending TOTP enrollment found. Call GET /api/auth/mfa/setup first." },
      { status: 400 }
    );
  }

  const result = await verifyTotpCode(session.uid, code, pendingSecret);
  if (!result.valid) {
    return NextResponse.json({ error: result.reason }, { status: 400 });
  }

  await commitTotpSecret(session.uid);

  return NextResponse.json({
    success: true,
    message: "MFA enrollment complete. TOTP is now required on every login.",
  });
}

/**
 * DELETE /api/auth/mfa/setup
 * Disables TOTP for the authenticated user. Requires a valid current TOTP code.
 * Body: { code: "123456" }
 */
export async function DELETE(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => ({}));
  const { code } = body;

  let secret: string | null = null;
  try {
    const res = await query<{ totp_secret: string | null }>(
      `SELECT totp_secret FROM users WHERE id = $1 AND totp_enabled = true LIMIT 1`,
      [session.uid]
    );
    secret = res.rows[0]?.totp_secret ?? null;
  } catch {
    return NextResponse.json({ error: "Database unavailable." }, { status: 500 });
  }

  if (!secret) {
    return NextResponse.json({ error: "TOTP is not enabled for this account." }, { status: 400 });
  }

  const result = await verifyTotpCode(session.uid, code, secret);
  if (!result.valid) {
    return NextResponse.json({ error: result.reason }, { status: 400 });
  }

  await query(
    `UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_enabled = false, updated_at = now() WHERE id = $1`,
    [session.uid]
  );

  return NextResponse.json({ success: true, message: "TOTP disabled successfully." });
}
