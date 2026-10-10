import crypto from "node:crypto";
import { query } from "@/lib/db";
import { BILLING_PLANS, BillingTier, getTenantSubscription } from "./plans";
import { verifyCommercialLicense, CommercialLicense } from "./licenses";
import { signControlPlaneData, verifyControlPlaneData } from "@/lib/fleet/commandSigning";
import { recordHashChainEvent } from "@/lib/fleet/fleet";

export type LicenseState =
  | "draft"
  | "active"
  | "suspended"
  | "grace_period"
  | "expired"
  | "revoked";

export type EntitlementFeatureKey =
  | "telemetryIngest"
  | "realTimeDetection"
  | "aiInvestigation"
  | "automatedRemediationTier1"
  | "governedRemediationTier2"
  | "dualApprovalTier3"
  | "siemConnectors"
  | "customRules"
  | "discordSlackAlerts"
  | "endpointFleet"
  | "complianceVault";

export interface TenantLicenseRecord {
  id: string;
  tenantId: string;
  licenseKey: string;
  tier: BillingTier;
  status: LicenseState;
  maxEndpoints: number;
  maxUsers: number;
  features: string[];
  activatedAt?: string;
  expiresAt: string;
  gracePeriodDays: number;
  signature: string;
  createdAt: string;
  updatedAt: string;
}

export interface OfflineCachePayload {
  tenantId: string;
  tier: BillingTier;
  maxEndpoints: number;
  allowedFeatures: string[];
  issuedAt: string;
  expiresAt: string;
  graceUntil: string;
}

export interface SignedOfflineCache {
  cacheToken: string;
  payload: OfflineCachePayload;
  signature: string;
}

export class EntitlementViolationError extends Error {
  public readonly status = 403;
  public readonly tenantId: string;
  public readonly feature?: string;

  constructor(message: string, tenantId: string, feature?: string) {
    super(message);
    this.name = "EntitlementViolationError";
    this.tenantId = tenantId;
    this.feature = feature;
  }
}

export class EntitlementService {
  private static inMemoryLicenses: Map<string, TenantLicenseRecord> = new Map([
    [
      "acme-tenant",
      {
        id: "lic-acme-default",
        tenantId: "acme-tenant",
        licenseKey: "lic_default_acme_key",
        tier: "professional",
        status: "active",
        maxEndpoints: 100,
        maxUsers: 25,
        features: [
          "telemetryIngest",
          "realTimeDetection",
          "aiInvestigation",
          "automatedRemediationTier1",
          "governedRemediationTier2",
          "dualApprovalTier3",
          "siemConnectors",
          "customRules",
          "discordSlackAlerts",
          "endpointFleet",
          "complianceVault",
        ],
        activatedAt: new Date(Date.now() - 86400000 * 30).toISOString(),
        expiresAt: new Date(Date.now() + 86400000 * 60).toISOString(),
        gracePeriodDays: 7,
        signature: "sig_mock_acme_license",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ],
  ]);

  private static inMemoryOfflineCaches: Map<string, SignedOfflineCache> = new Map();

  /**
   * Retrieves the active or registered commercial license for a tenant.
   */
  public static async getLicense(tenantId: string): Promise<TenantLicenseRecord | null> {
    if (this.inMemoryLicenses.has(tenantId)) {
      return this.inMemoryLicenses.get(tenantId) || null;
    }

    try {
      const res = await query<any>(
        `SELECT id, tenant_id, license_key, tier, status, max_endpoints, max_users, features,
                activated_at, expires_at, grace_period_days, signature, created_at, updated_at
         FROM tenant_licenses WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
        [tenantId]
      );
      if (res.rows.length > 0) {
        const row = res.rows[0];
        const record: TenantLicenseRecord = {
          id: row.id,
          tenantId: row.tenant_id,
          licenseKey: row.license_key,
          tier: row.tier as BillingTier,
          status: row.status as LicenseState,
          maxEndpoints: Number(row.max_endpoints),
          maxUsers: Number(row.max_users),
          features: Array.isArray(row.features) ? row.features : [],
          activatedAt: row.activated_at ? new Date(row.activated_at).toISOString() : undefined,
          expiresAt: new Date(row.expires_at).toISOString(),
          gracePeriodDays: Number(row.grace_period_days || 7),
          signature: row.signature,
          createdAt: new Date(row.created_at).toISOString(),
          updatedAt: new Date(row.updated_at).toISOString(),
        };
        this.inMemoryLicenses.set(tenantId, record);
        return record;
      }
    } catch {
      // Fallback
    }

    return null;
  }

  /**
   * Computes the current license state including expiration and grace period detection.
   */
  public static async getLicenseState(tenantId: string): Promise<{
    state: LicenseState;
    license?: TenantLicenseRecord;
    graceUntil?: string;
    reason?: string;
  }> {
    const license = await this.getLicense(tenantId);
    if (!license) {
      // If no explicit license exists, fallback to subscription tier
      const sub = await getTenantSubscription(tenantId);
      if (sub.status === "active" || sub.status === "trialing") {
        return { state: "active" };
      }
      return { state: "expired", reason: `No active license or subscription found for tenant '${tenantId}'` };
    }

    if (license.status === "suspended" || license.status === "revoked" || license.status === "draft") {
      return { state: license.status, license, reason: `License is ${license.status}. Access blocked.` };
    }

    const now = Date.now();
    const expiryTime = new Date(license.expiresAt).getTime();
    const gracePeriodMs = license.gracePeriodDays * 86400 * 1000;
    const graceUntilTime = expiryTime + gracePeriodMs;
    const graceUntil = new Date(graceUntilTime).toISOString();

    if (now <= expiryTime) {
      return { state: "active", license };
    }

    if (now <= graceUntilTime) {
      license.status = "grace_period";
      return {
        state: "grace_period",
        license,
        graceUntil,
        reason: `License expired on ${license.expiresAt}. Operating under ${license.gracePeriodDays}-day grace period until ${graceUntil}.`,
      };
    }

    license.status = "expired";
    return {
      state: "expired",
      license,
      graceUntil,
      reason: `License expired on ${license.expiresAt} and grace period ended on ${graceUntil}. Access permanently blocked.`,
    };
  }

  /**
   * Activates a commercial license key for a tenant.
   */
  public static async activateLicense(params: {
    tenantId: string;
    licenseKey: string;
  }): Promise<TenantLicenseRecord> {
    const verification = verifyCommercialLicense(params.licenseKey);
    if (!verification.valid || !verification.payload) {
      throw new Error(`Invalid license key: ${verification.reason || "Verification failed"}`);
    }

    const p = verification.payload;
    if (p.tenantId !== params.tenantId && p.tenantId !== "*") {
      throw new Error(
        `License tenant mismatch: License was issued to '${p.tenantId}', not caller '${params.tenantId}'`
      );
    }

    const id = `lic-${crypto.randomBytes(8).toString("hex")}`;
    const now = new Date().toISOString();

    const record: TenantLicenseRecord = {
      id,
      tenantId: params.tenantId,
      licenseKey: params.licenseKey,
      tier: p.tier,
      status: "active",
      maxEndpoints: p.maxEndpoints,
      maxUsers: p.maxUsers,
      features: p.features,
      activatedAt: now,
      expiresAt: p.expiresAt,
      gracePeriodDays: 7,
      signature: verification.payload ? crypto.createHash("sha256").update(params.licenseKey).digest("hex") : "",
      createdAt: now,
      updatedAt: now,
    };

    this.inMemoryLicenses.set(params.tenantId, record);

    try {
      await query(
        `INSERT INTO tenant_licenses (
          id, tenant_id, license_key, tier, status, max_endpoints, max_users, features,
          activated_at, expires_at, grace_period_days, signature, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, NOW(), $8, 7, $9, NOW(), NOW())
        ON CONFLICT (id) DO UPDATE SET status = 'active', updated_at = NOW()`,
        [
          id,
          params.tenantId,
          params.licenseKey,
          p.tier,
          p.maxEndpoints,
          p.maxUsers,
          p.features,
          p.expiresAt,
          record.signature,
        ]
      );
    } catch {
      // Fallback
    }

    await recordHashChainEvent({
      tenantId: params.tenantId,
      eventType: "COMMERCIAL_LICENSE_ACTIVATED",
      actorId: `tenant:${params.tenantId}`,
      payload: {
        licenseId: id,
        tier: p.tier,
        maxEndpoints: p.maxEndpoints,
        expiresAt: p.expiresAt,
      },
    });

    return record;
  }


  /**
   * Non-Negotiable Rule 4 & Entitlement Verification Guard:
   * "Every request resolves User -> Org -> Subscription -> License -> Entitlement -> Resource."
   * Server-side gate for all privileged features.
   */
  public static async require(params: {
    tenantId: string;
    feature?: EntitlementFeatureKey;
    currentEndpointsCount?: number;
    context?: string;
    throwOnViolation?: boolean;
  }): Promise<{
    allowed: boolean;
    reason?: string;
    tier: BillingTier;
    state: LicenseState;
  }> {
    const throwOnViolation = params.throwOnViolation !== false;
    const { state, license, reason } = await this.getLicenseState(params.tenantId);

    // Fail closed if license is expired, suspended, or revoked
    if (state === "expired" || state === "suspended" || state === "revoked") {
      const errReason = `Access denied under fail-closed security policy: ${reason || `License state is '${state}'.`}`;
      if (throwOnViolation) {
        throw new EntitlementViolationError(errReason, params.tenantId, params.feature);
      }
      return { allowed: false, reason: errReason, tier: license?.tier || "community", state };
    }

    // Resolve effective tier
    let effectiveTier: BillingTier = license?.tier || "community";
    if (!license) {
      const sub = await getTenantSubscription(params.tenantId);
      effectiveTier = sub.tier;
    }

    const planDef = BILLING_PLANS[effectiveTier];

    // Feature Entitlement Check
    if (params.feature) {
      let isFeatureAllowed = false;

      // Check plan definition
      if (planDef && planDef.features && (planDef.features as any)[params.feature] === true) {
        isFeatureAllowed = true;
      }

      // Check explicit custom features in license
      if (license && license.features && license.features.includes(params.feature)) {
        isFeatureAllowed = true;
      }

      // Enterprise / Pro overrides for specific named features
      if (params.feature === "endpointFleet" || params.feature === "complianceVault") {
        isFeatureAllowed = effectiveTier === "professional" || effectiveTier === "enterprise";
      }

      if (!isFeatureAllowed) {
        const errReason = `Feature '${params.feature}' is not entitled for tier '${effectiveTier}'. Upgrade required.`;
        if (throwOnViolation) {
          throw new EntitlementViolationError(errReason, params.tenantId, params.feature);
        }
        return { allowed: false, reason: errReason, tier: effectiveTier, state };
      }
    }

    // Endpoint Quota Check
    if (typeof params.currentEndpointsCount === "number") {
      const quota = license?.maxEndpoints || planDef.maxEndpoints;
      if (params.currentEndpointsCount >= quota) {
        const errReason = `Endpoint quota exceeded: Tenant '${params.tenantId}' has enrolled ${params.currentEndpointsCount}/${quota} allowed endpoints.`;
        if (throwOnViolation) {
          throw new EntitlementViolationError(errReason, params.tenantId, "endpointQuota");
        }
        return { allowed: false, reason: errReason, tier: effectiveTier, state };
      }
    }

    return {
      allowed: true,
      tier: effectiveTier,
      state,
      reason: state === "grace_period" ? reason : undefined,
    };
  }

  /**
   * Generates a cryptographically signed offline entitlement cache for disconnected environments.
   */
  public static async generateOfflineEntitlementCache(params: {
    tenantId: string;
    validityDays?: number;
    graceDays?: number;
  }): Promise<SignedOfflineCache> {
    const validityDays = params.validityDays || 30;
    const graceDays = params.graceDays || 7;

    const license = await this.getLicense(params.tenantId);
    const tier: BillingTier = license?.tier || "professional";
    const maxEndpoints = license?.maxEndpoints || 100;
    const allowedFeatures = license?.features || Object.keys(BILLING_PLANS[tier].features);

    const now = Date.now();
    const issuedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + validityDays * 86400 * 1000).toISOString();
    const graceUntil = new Date(now + (validityDays + graceDays) * 86400 * 1000).toISOString();

    const payload: OfflineCachePayload = {
      tenantId: params.tenantId,
      tier,
      maxEndpoints,
      allowedFeatures,
      issuedAt,
      expiresAt,
      graceUntil,
    };

    // Canonical payload string
    const canonical = `${payload.tenantId}|${payload.tier}|${payload.maxEndpoints}|${payload.allowedFeatures.sort().join(",")}|${payload.issuedAt}|${payload.expiresAt}|${payload.graceUntil}`;
    const signature = signControlPlaneData(canonical);

    const cacheToken = Buffer.from(JSON.stringify({ payload, signature })).toString("base64url");
    const signedCache: SignedOfflineCache = { cacheToken, payload, signature };

    this.inMemoryOfflineCaches.set(params.tenantId, signedCache);

    try {
      await query(
        `INSERT INTO offline_entitlement_caches (
          id, tenant_id, tier, max_endpoints, allowed_features, cache_token, signature, issued_at, expires_at, grace_until, is_revoked
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)`,
        [
          `off-${crypto.randomBytes(8).toString("hex")}`,
          params.tenantId,
          tier,
          maxEndpoints,
          allowedFeatures,
          cacheToken,
          signature,
          issuedAt,
          expiresAt,
          graceUntil,
        ]
      );
    } catch {
      // Fallback
    }

    return signedCache;
  }

  /**
   * Cryptographically verifies an offline entitlement cache token.
   */
  public static verifyOfflineEntitlementCache(cacheToken: string): {
    valid: boolean;
    payload?: OfflineCachePayload;
    inGracePeriod?: boolean;
    reason?: string;
  } {
    try {
      const decoded = JSON.parse(Buffer.from(cacheToken, "base64url").toString("utf8"));
      const payload: OfflineCachePayload = decoded.payload;
      const signature: string = decoded.signature;

      if (!payload || !signature) {
        return { valid: false, reason: "Malformed offline cache token structure." };
      }

      const canonical = `${payload.tenantId}|${payload.tier}|${payload.maxEndpoints}|${payload.allowedFeatures.sort().join(",")}|${payload.issuedAt}|${payload.expiresAt}|${payload.graceUntil}`;
      const isSigValid = verifyControlPlaneData(canonical, signature);

      if (!isSigValid) {
        return { valid: false, reason: "Cryptographic signature verification failed on offline entitlement cache." };
      }

      const now = Date.now();
      const expiry = new Date(payload.expiresAt).getTime();
      const grace = new Date(payload.graceUntil).getTime();

      if (now <= expiry) {
        return { valid: true, payload, inGracePeriod: false };
      }

      if (now <= grace) {
        return {
          valid: true,
          payload,
          inGracePeriod: true,
          reason: `Offline cache expired on ${payload.expiresAt}. Operating under grace period until ${payload.graceUntil}.`,
        };
      }

      return {
        valid: false,
        payload,
        inGracePeriod: false,
        reason: `Offline cache expired on ${payload.expiresAt} and grace period ended on ${payload.graceUntil}. Access blocked.`,
      };
    } catch (err: unknown) {
      return { valid: false, reason: `Failed to parse offline cache token: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  /**
   * Helper to manually update license status (e.g. suspension, revocation, or testing).
   */
  public static async setLicenseStatus(tenantId: string, status: LicenseState): Promise<void> {
    const license = await this.getLicense(tenantId);
    if (license) {
      license.status = status;
      license.updatedAt = new Date().toISOString();
      this.inMemoryLicenses.set(tenantId, license);
    } else {
      this.inMemoryLicenses.set(tenantId, {
        id: `lic-${tenantId}`,
        tenantId,
        licenseKey: "",
        tier: "community",
        status,
        maxEndpoints: 0,
        maxUsers: 0,
        features: [],
        expiresAt: new Date().toISOString(),
        gracePeriodDays: 0,
        signature: "",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }
    try {
      await query(`UPDATE tenant_licenses SET status = $1, updated_at = NOW() WHERE tenant_id = $2`, [status, tenantId]);
    } catch {
      // Fallback
    }
  }
}
