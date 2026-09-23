import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { authenticator } from "otplib";
import qrcode from "qrcode";
import crypto from "crypto";
import { setCache, getCache } from "./redis.js";

const JWT_SECRET = (() => {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (process.env.NODE_ENV === "production") {
    throw new Error("FATAL: JWT_SECRET environment variable is required in production mode.");
  }
  return "shielddesk_ephemeral_dev_secret_key";
})();
const ACCESS_TOKEN_EXPIRY = "1h";
const SALT_ROUNDS = 12;

export interface TokenPayload {
  sub: string;           // User ID (UUID)
  tenant_id: string;     // Tenant ID (e.g. 'ten_acme123')
  role: "owner" | "admin" | "member" | "viewer";
  mfa: boolean;          // True if full MFA passed
}

// Generate Access Token (1 hour expiry, HS256)
export function signAccessToken(payload: TokenPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

// Verify Access Token
export function verifyAccessToken(token: string): TokenPayload {
  return jwt.verify(token, JWT_SECRET) as TokenPayload;
}

// Hash password with bcrypt
export async function hashPassword(plain: string): Promise<string> {
  return await bcrypt.hash(plain, SALT_ROUNDS);
}

// Compare password with hash
export async function comparePassword(plain: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(plain, hash);
}

// Generate secure random refresh token string and its hash
export async function generateRefreshToken(): Promise<{ token: string; hash: string }> {
  const token = crypto.randomBytes(40).toString("hex");
  const hash = await bcrypt.hash(token, 10);
  return { token, hash };
}

// TOTP MFA setup
export async function generateMfaSetup(email: string, issuer = "ShieldDesk SOC"): Promise<{ secret: string; qrCodeUrl: string }> {
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(email, issuer, secret);
  const qrCodeUrl = await qrcode.toDataURL(otpauth);
  return { secret, qrCodeUrl };
}

// Verify TOTP code
export function verifyMfaToken(token: string, secret: string): boolean {
  return authenticator.check(token, secret);
}

// Agent Tenant Token Management (Redis TTL 5 minutes)
export async function issueAgentToken(tenantId: string): Promise<string> {
  const token = `agt_${crypto.randomBytes(24).toString("hex")}`;
  // Store key: agent:token:{token}, value: tenant_id, TTL 300s (5 min)
  await setCache(`agent:token:${token}`, tenantId, 300);
  return token;
}

// Validate Agent Token against Redis
export async function validateAgentToken(token: string): Promise<string | null> {
  return await getCache(`agent:token:${token}`);
}
