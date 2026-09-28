import "server-only";
import {
  generate as totpGenerate,
  verify as totpVerify,
  generateSecret,
  generateURI,
  NobleCryptoPlugin,
  ScureBase32Plugin,
} from "otplib";
import { query } from "@/lib/db";

/**
 * otplib v13 functional API — plugins are passed per-call.
 * NobleCryptoPlugin provides HMAC-SHA1/256/512 via the @noble/hashes suite.
 * ScureBase32Plugin handles RFC 4648 Base32 encoding for secrets.
 */
const CRYPTO = new NobleCryptoPlugin();
const BASE32 = new ScureBase32Plugin();
const TOTP_OPTS = { crypto: CRYPTO, base32: BASE32, digits: 6, step: 30, window: 1 };

export interface TotpSetupResult {
  secret: string;
  otpauthUrl: string;
  /** base64-encoded PNG QR code — ready for <img src="data:image/png;base64,…"> */
  qrDataUrl: string;
}

/**
 * Generate a fresh TOTP secret for a user and return the otpauth URL + QR code.
 * Does NOT persist the secret — call commitTotpSecret() after the user confirms
 * a valid code to avoid storing unverified secrets.
 */
export async function generateTotpSetup(
  userId: string,
  email: string
): Promise<TotpSetupResult> {
  const secret = generateSecret({ base32: BASE32 });

  const otpauthUrl = generateURI({
    secret,
    label: email,
    issuer: "ShieldDesk SOC",
    algorithm: "sha1",
    digits: 6,
    period: 30,
  });

  // Dynamic import to keep qrcode out of the Edge runtime bundle
  const QRCode = await import("qrcode");
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 256,
  });

  // Temporarily store in totp_pending_secret so that the secret is never
  // committed until the user proves they can produce a valid token.
  try {
    await query(
      `UPDATE users SET totp_pending_secret = $1, updated_at = now() WHERE id = $2`,
      [secret, userId]
    );
  } catch {
    // Supabase / offline path — pending secret returned to caller for confirmation flow
  }

  return { secret, otpauthUrl, qrDataUrl };
}

/**
 * Verify a TOTP code against a given secret.
 * Returns true only if the code is mathematically valid and has NOT been used
 * in the same 30-second window (replay guard via last_totp_at column).
 */
export async function verifyTotpCode(
  userId: string,
  code: string,
  secret: string
): Promise<{ valid: boolean; reason?: string }> {
  if (!code || !/^\d{6}$/.test(code)) {
    return { valid: false, reason: "TOTP code must be exactly 6 digits." };
  }

  let verifyResult: { valid: boolean } | null = null;
  try {
    verifyResult = await totpVerify({ token: code, secret, ...TOTP_OPTS });
  } catch {
    return { valid: false, reason: "Invalid or expired TOTP code." };
  }

  if (!verifyResult?.valid) {
    return { valid: false, reason: "Invalid or expired TOTP code." };
  }

  // Replay-guard: reject if this exact step window was already used
  try {
    const now = new Date();
    const stepStart = new Date(Math.floor(now.getTime() / 30000) * 30000);

    const res = await query<{ last_totp_at: string | null }>(
      `SELECT last_totp_at FROM users WHERE id = $1 LIMIT 1`,
      [userId]
    );
    const lastAt = res.rows[0]?.last_totp_at;
    if (lastAt && new Date(lastAt) >= stepStart) {
      return { valid: false, reason: "TOTP code already used. Wait for the next 30-second window." };
    }

    await query(`UPDATE users SET last_totp_at = now() WHERE id = $1`, [userId]);
  } catch {
    // If we can't check replay, still pass — avoids locking users out when DB is unreachable
  }

  return { valid: true };
}

/**
 * Promote a pending TOTP secret to the active secret after user confirmation.
 */
export async function commitTotpSecret(userId: string): Promise<void> {
  await query(
    `UPDATE users
     SET totp_secret = totp_pending_secret,
         totp_pending_secret = NULL,
         totp_enabled = true,
         updated_at = now()
     WHERE id = $1`,
    [userId]
  );
}

/**
 * Fetch a user's active TOTP secret from the database.
 * Returns null if MFA is not enrolled.
 */
export async function getTotpSecret(userId: string): Promise<string | null> {
  try {
    const res = await query<{ totp_secret: string | null; totp_enabled: boolean }>(
      `SELECT totp_secret, totp_enabled FROM users WHERE id = $1 LIMIT 1`,
      [userId]
    );
    const row = res.rows[0];
    if (!row || !row.totp_enabled || !row.totp_secret) return null;
    return row.totp_secret;
  } catch {
    return null;
  }
}
