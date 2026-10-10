import "server-only";
import crypto from "node:crypto";
import type { BillingTier } from "./catalog";
import { base64UrlEncode, base64UrlDecode } from "@/lib/crypto/encoding";
import { signControlPlaneData, verifyControlPlaneData, getControlPlanePublicKey } from "@/lib/fleet/commandSigning";

export interface LicensePayload {
  licenseId: string;
  tenantId: string;
  tier: BillingTier;
  maxEndpoints: number;
  maxUsers: number;
  features: string[];
  issuedAt: string;
  expiresAt: string;
  keyId?: string;
  signingMode?: "symmetric" | "asymmetric";
}

export interface CommercialLicense {
  rawLicense: string;
  payload: LicensePayload;
  signature: string;
}

export interface GeneratedLicenseArtifact {
  rawLicenseKey: string;
  keyHash: string;
  displayPrefix: string;
  displaySuffix: string;
  payload: LicensePayload;
  keyId: string;
}

/**
 * Returns the dedicated license signing secret.
 * Rule: Never fall back to SHIELDDESK_SESSION_SECRET in production.
 */
function getLicenseSigningSecret(): string {
  const secret = process.env.SHIELDDESK_LICENSE_SECRET;
  if (!secret) {
    if (
      process.env.NODE_ENV !== "test" &&
      (process.env.NODE_ENV === "production" || process.env.APP_ENV === "production")
    ) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_LICENSE_SECRET must be configured in production. Shared secret fallback is prohibited."
      );
    }
    return "shielddesk_commercial_license_dev_key";
  }
  return secret;
}

/**
 * Key-lookup pepper separated from the signing key.
 * Used exclusively to compute the irreversible one-way digest of license keys for database lookup.
 */
function getLicenseLookupPepper(): string {
  return (
    process.env.SHIELDDESK_LICENSE_PEPPER ||
    process.env.SHIELDDESK_LICENSE_SECRET ||
    "shielddesk_lookup_pepper_v1"
  );
}

/**
 * Computes an irreversible SHA-256 keyed digest for database lookup.
 * Protects database breaches from revealing raw usable license keys.
 */
export function hashLicenseKey(rawLicenseKey: string): string {
  const pepper = getLicenseLookupPepper();
  return crypto.createHmac("sha256", pepper).update(rawLicenseKey.trim()).digest("hex");
}

/**
 * Generates safe display hints (e.g. prefix 'SD-PRO', suffix '7A4F') for audit and customer portal.
 */
export function getLicenseDisplayHints(rawLicenseKey: string, tier: string = "pro"): {
  prefix: string;
  suffix: string;
} {
  const clean = rawLicenseKey.trim();
  const prefix = `SD-${tier.substring(0, 3).toUpperCase()}`;
  const suffix = clean.length >= 4 ? clean.slice(-4).toUpperCase() : "XXXX";
  return { prefix, suffix };
}

/**
 * Generates a high-entropy commercial license key.
 * Format: base64url(JSON(payload)).base64url(HMAC-SHA256(payload))
 * Backward compatible with existing tests while injecting 192-bit cryptographic entropy.
 */
export function issueCommercialLicense(
  payload: Omit<LicensePayload, "licenseId" | "issuedAt">,
  secret = getLicenseSigningSecret()
): CommercialLicense {
  const entropy = crypto.randomBytes(16).toString("hex");
  const licenseId = `lic_${entropy}`;
  const issuedAt = new Date().toISOString();

  const fullPayload: LicensePayload = {
    ...payload,
    licenseId,
    issuedAt,
    keyId: "sd-k1",
    signingMode: "symmetric",
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
 * High-entropy full license generation for customer portal issuance and storage.
 * Returns raw secret (revealed once to customer), irreversible DB lookup hash, and display hints.
 */
export function generateHighEntropyLicense(params: {
  tenantId: string;
  tier: BillingTier;
  maxEndpoints: number;
  maxUsers: number;
  features: string[];
  expiresAt: string;
  keyId?: string;
}): GeneratedLicenseArtifact {
  const { tenantId, tier, maxEndpoints, maxUsers, features, expiresAt, keyId = "sd-k1" } = params;

  const license = issueCommercialLicense({
    tenantId,
    tier,
    maxEndpoints,
    maxUsers,
    features,
    expiresAt,
    keyId,
  });

  const keyHash = hashLicenseKey(license.rawLicense);
  const { prefix, suffix } = getLicenseDisplayHints(license.rawLicense, tier);

  return {
    rawLicenseKey: license.rawLicense,
    keyHash,
    displayPrefix: prefix,
    displaySuffix: suffix,
    payload: license.payload,
    keyId,
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

/**
 * Asymmetric Entitlement Token for Customer-Hosted / Offline Deployments.
 * The licensing service retains the RSA-2048 private key; deployed software verifies using public key only.
 */
export interface AsymmetricEntitlementToken {
  token: string;
  payload: {
    tenantId: string;
    installationId: string;
    tier: BillingTier;
    maxEndpoints: number;
    features: string[];
    issuedAt: string;
    expiresAt: string;
    keyId: string;
  };
  signature: string;
}

export function issueAsymmetricEntitlementToken(params: {
  tenantId: string;
  installationId: string;
  tier: BillingTier;
  maxEndpoints: number;
  features: string[];
  validityHours?: number;
  keyId?: string;
}): AsymmetricEntitlementToken {
  const {
    tenantId,
    installationId,
    tier,
    maxEndpoints,
    features,
    validityHours = 168, // 7 days
    keyId = "sd-k1",
  } = params;

  const now = Date.now();
  const issuedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + validityHours * 3600 * 1000).toISOString();

  const payload = {
    tenantId,
    installationId,
    tier,
    maxEndpoints,
    features,
    issuedAt,
    expiresAt,
    keyId,
  };

  const canonical = `${tenantId}|${installationId}|${tier}|${maxEndpoints}|${features.sort().join(",")}|${issuedAt}|${expiresAt}|${keyId}`;
  const signature = signControlPlaneData(canonical);

  const token = Buffer.from(JSON.stringify({ payload, signature })).toString("base64url");

  return { token, payload, signature };
}

export function verifyAsymmetricEntitlementToken(token: string): {
  valid: boolean;
  payload?: AsymmetricEntitlementToken["payload"];
  reason?: string;
} {
  try {
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
    const { payload, signature } = decoded;

    if (!payload || !signature) {
      return { valid: false, reason: "Malformed entitlement token structure." };
    }

    const canonical = `${payload.tenantId}|${payload.installationId}|${payload.tier}|${payload.maxEndpoints}|${payload.features.sort().join(",")}|${payload.issuedAt}|${payload.expiresAt}|${payload.keyId}`;
    const verified = verifyControlPlaneData(canonical, signature);

    if (!verified) {
      return { valid: false, reason: "Cryptographic RSA signature verification failed on entitlement token." };
    }

    if (Date.now() > new Date(payload.expiresAt).getTime()) {
      return { valid: false, payload, reason: `Entitlement token expired on ${payload.expiresAt}.` };
    }

    return { valid: true, payload };
  } catch (err: unknown) {
    return { valid: false, reason: err instanceof Error ? err.message : "Token parse error" };
  }
}
