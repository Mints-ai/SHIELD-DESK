import "server-only";
import crypto from "node:crypto";
import type { BillingTier } from "./plans";
import { base64UrlEncode, base64UrlDecode } from "@/lib/crypto/encoding";

export interface LicensePayload {
  licenseId: string;
  tenantId: string;
  tier: BillingTier;
  maxEndpoints: number;
  maxUsers: number;
  features: string[];
  issuedAt: string;
  expiresAt: string;
}

export interface CommercialLicense {
  rawLicense: string;
  payload: LicensePayload;
  signature: string;
}

function getLicenseSigningSecret(): string {
  const secret = process.env.SHIELDDESK_LICENSE_SECRET || process.env.SHIELDDESK_SESSION_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_LICENSE_SECRET or SHIELDDESK_SESSION_SECRET must be configured in production."
      );
    }
    return "shielddesk_commercial_license_dev_key";
  }
  return secret;
}

/**
 * Generates a cryptographically signed commercial license key.
 * Format: base64url(JSON(payload)).base64url(HMAC-SHA256(payload))
 */
export function issueCommercialLicense(
  payload: Omit<LicensePayload, "licenseId" | "issuedAt">,
  secret = getLicenseSigningSecret()
): CommercialLicense {
  const licenseId = `lic_${crypto.randomUUID()}`;
  const issuedAt = new Date().toISOString();

  const fullPayload: LicensePayload = {
    ...payload,
    licenseId,
    issuedAt,
  };

  const serialized = JSON.stringify(fullPayload);
  const encodedPayload = base64UrlEncode(serialized);

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(encodedPayload);
  const signature = base64UrlEncode(hmac.digest());

  const rawLicense = `${encodedPayload}.${signature}`;

  return {
    rawLicense,
    payload: fullPayload,
    signature,
  };
}

/**
 * Cryptographically verifies a commercial license key.
 * Checks HMAC signature, expiration date, and payload structure.
 */
export function verifyCommercialLicense(
  rawLicense: string,
  secret = getLicenseSigningSecret()
): { valid: boolean; payload?: LicensePayload; reason?: string } {
  if (!rawLicense || typeof rawLicense !== "string") {
    return { valid: false, reason: "License key is missing or empty." };
  }

  const parts = rawLicense.split(".");
  if (parts.length !== 2) {
    return { valid: false, reason: "Malformed license key structure." };
  }

  const [encodedPayload, receivedSig] = parts;
  if (!encodedPayload || !receivedSig) {
    return { valid: false, reason: "Incomplete license token segments." };
  }

  try {
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(encodedPayload);
    const expectedSig = base64UrlEncode(hmac.digest());

    const receivedSigBuf = Buffer.from(receivedSig);
    const expectedSigBuf = Buffer.from(expectedSig);

    if (
      receivedSigBuf.length !== expectedSigBuf.length ||
      !crypto.timingSafeEqual(receivedSigBuf, expectedSigBuf)
    ) {
      return { valid: false, reason: "Cryptographic license signature verification failed." };
    }

    const payloadJson = base64UrlDecode(encodedPayload);
    const payload: LicensePayload = JSON.parse(payloadJson);

    // Expiration check
    const expiresTime = new Date(payload.expiresAt).getTime();
    if (isNaN(expiresTime) || Date.now() > expiresTime) {
      return { valid: false, payload, reason: `License expired on ${payload.expiresAt}.` };
    }

    return {
      valid: true,
      payload,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "License parsing error";
    return { valid: false, reason: msg };
  }
}
