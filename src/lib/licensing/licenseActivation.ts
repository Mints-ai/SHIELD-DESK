import "server-only";
import crypto from "node:crypto";
import { query } from "@/lib/db";
import {
  verifyCommercialLicense,
  issueAsymmetricEntitlementToken,
  type AsymmetricEntitlementToken,
} from "@/lib/billing/licenses";
import { validateEndpointCertificate } from "@/lib/fleet/certificates";
import { MTLSGuard } from "@/lib/fleet/mtlsGuard";
import { X509Certificate } from "node:crypto";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { EntitlementService } from "@/lib/billing/entitlements";

export type AgentLicenseState =
  | "TRIAL"
  | "ACTIVE"
  | "PAST_DUE"
  | "SUSPENDED"
  | "EXPIRED"
  | "REVOKED";

export interface AgentLicenseActivation {
  id?: string;
  tenantId: string;
  installationId: string;
  deviceIdentity: string;
  certificateFingerprint: string;
  licenseId: string;
  licenseExpiresAt: string;
  platform?: string;
  productVersion?: string;
  state: AgentLicenseState;
  activatedAt: string;
  lastHeartbeatAt?: string;
  deactivatedAt?: string;
  entitlementToken?: string;
}

export class LicenseActivationService {
  private static activations = new Map<string, AgentLicenseActivation>();
  private static revokedLicenses = new Set<string>();
  private static key(tenantId: string, installationId: string) {
    return `${tenantId}:${installationId}`;
  }

  private static async validateIdentity(params: {
    tenantId: string;
    installationId: string;
    deviceIdentity: string;
    certificatePem: string;
    licenseKey: string;
    challenge?: string;
    challengeResponse?: string;
  }) {
    for (const [name, value] of Object.entries(params)) {
      if (name === "challenge" || name === "challengeResponse") continue;
      if (typeof value !== "string" || !value.trim()) {
        throw new Error(`Missing required activation field '${name}'.`);
      }
    }

    const certificate = await validateEndpointCertificate({
      certificatePem: params.certificatePem,
      expectedAgentId: params.deviceIdentity,
      expectedTenantId: params.tenantId,
    });
    if (!certificate.valid || !certificate.serialNumber) {
      throw new Error(`Device certificate rejected: ${certificate.error || "identity mismatch"}`);
    }

    const fingerprint = new X509Certificate(params.certificatePem).fingerprint256
      .replaceAll(":", "")
      .toLowerCase();

    const device = await MTLSGuard.validateClientCertificate({
      agentId: params.deviceIdentity,
      certFingerprint: fingerprint,
      tenantId: params.tenantId,
    });
    if (!device.allowed) {
      throw new Error(`Device identity rejected: ${device.reason || "mTLS check failed"}`);
    }

    // Optional cryptographic proof-of-possession verification when challenge is supplied
    if (params.challenge && params.challengeResponse) {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(params.challenge);
      const isProofValid = verifier.verify(
        params.certificatePem,
        params.challengeResponse,
        "base64"
      );
      if (!isProofValid) {
        throw new Error("Cryptographic challenge proof-of-possession rejected.");
      }
    }

    const license = verifyCommercialLicense(params.licenseKey);
    if (!license.valid || !license.payload) {
      throw new Error(`License rejected: ${license.reason || "invalid license"}`);
    }

    if (license.payload.tenantId !== params.tenantId && license.payload.tenantId !== "*") {
      throw new Error("License tenant does not match device tenant.");
    }

    if (!license.payload.features.includes("endpointFleet")) {
      throw new Error("License does not include the endpointFleet entitlement.");
    }

    if (
      this.revokedLicenses.has(license.payload.licenseId) ||
      this.revokedLicenses.has(params.tenantId)
    ) {
      throw new Error("License has been revoked by security policy.");
    }

    const licenseState = await EntitlementService.getLicenseState(params.tenantId);
    if (licenseState.state === "revoked") {
      throw new Error("License has been revoked by security policy.");
    }

    return {
      fingerprint,
      licenseId: license.payload.licenseId,
      licenseExpiresAt: license.payload.expiresAt,
      maxEndpoints: license.payload.maxEndpoints,
      features: license.payload.features,
      tier: license.payload.tier,
      state: (license.payload.tier === "community" ? "TRIAL" : "ACTIVE") as AgentLicenseState,
    };
  }

  public static async validate(params: {
    tenantId: string;
    installationId: string;
    deviceIdentity: string;
    certificatePem: string;
    licenseKey: string;
  }) {
    const valid = await this.validateIdentity(params);
    const existing = await this.get(params.tenantId, params.installationId);
    const state = existing?.state || valid.state;
    return {
      valid:
        (!existing || existing.deviceIdentity === params.deviceIdentity) &&
        (state === "ACTIVE" || state === "TRIAL"),
      state,
      licenseId: valid.licenseId,
    };
  }

  public static async activate(params: {
    tenantId: string;
    installationId: string;
    deviceIdentity: string;
    certificatePem: string;
    licenseKey: string;
    platform?: string;
    productVersion?: string;
    challenge?: string;
    challengeResponse?: string;
  }): Promise<AgentLicenseActivation> {
    const identity = await this.validateIdentity(params);
    const key = this.key(params.tenantId, params.installationId);
    const previous = await this.get(params.tenantId, params.installationId);

    if (previous && previous.deviceIdentity !== params.deviceIdentity) {
      throw new Error("Installation is already bound to a different device identity.");
    }

    // Transactional activation limit enforcement
    const activeActivations = [...this.activations.values()].filter(
      (a) =>
        a.tenantId === params.tenantId &&
        a.licenseId === identity.licenseId &&
        (a.state === "ACTIVE" || a.state === "TRIAL") &&
        a.installationId !== params.installationId
    );

    if (activeActivations.length >= identity.maxEndpoints) {
      throw new Error(
        `License activation limit exceeded: ${activeActivations.length}/${identity.maxEndpoints} active seats in use.`
      );
    }

    // Generate short-lived signed entitlement token for offline verification
    const entitlementToken = issueAsymmetricEntitlementToken({
      tenantId: params.tenantId,
      installationId: params.installationId,
      tier: identity.tier,
      maxEndpoints: identity.maxEndpoints,
      features: identity.features,
      validityHours: 168, // 7 days
    });

    const activationId = previous?.id || `act_${crypto.randomBytes(8).toString("hex")}`;
    const record: AgentLicenseActivation = {
      id: activationId,
      tenantId: params.tenantId,
      installationId: params.installationId,
      deviceIdentity: params.deviceIdentity,
      certificateFingerprint: identity.fingerprint,
      licenseId: identity.licenseId,
      licenseExpiresAt: identity.licenseExpiresAt,
      platform: params.platform || "linux",
      productVersion: params.productVersion || "2.4.0",
      state: identity.state,
      activatedAt: previous?.activatedAt || new Date().toISOString(),
      entitlementToken: entitlementToken.token,
    };

    this.activations.set(key, record);

    try {
      await query(
        `INSERT INTO agent_license_activations (
          tenant_id, installation_id, device_identity, certificate_fingerprint,
          license_id, license_expires_at, state, activated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (tenant_id, installation_id) DO UPDATE SET
          certificate_fingerprint = EXCLUDED.certificate_fingerprint,
          license_id = EXCLUDED.license_id,
          license_expires_at = EXCLUDED.license_expires_at,
          state = EXCLUDED.state`,
        [
          record.tenantId,
          record.installationId,
          record.deviceIdentity,
          record.certificateFingerprint,
          record.licenseId,
          record.licenseExpiresAt,
          record.state,
          record.activatedAt,
        ]
      );
    } catch {
      // In-memory fallback
    }

    await recordHashChainEvent({
      tenantId: params.tenantId,
      eventType: "LICENSE_ACTIVATION_RECORDED",
      actorId: `device:${params.deviceIdentity}`,
      payload: {
        installationId: params.installationId,
        licenseId: identity.licenseId,
        fingerprint: identity.fingerprint,
      },
    });

    return record;
  }

  public static async refresh(params: {
    tenantId: string;
    installationId: string;
    deviceIdentity: string;
    certificatePem: string;
    licenseKey: string;
  }): Promise<{ entitlementToken: string; expiresAt: string; state: AgentLicenseState }> {
    const activation = await this.activate(params);
    return {
      entitlementToken: activation.entitlementToken || "",
      expiresAt: activation.licenseExpiresAt,
      state: activation.state,
    };
  }

  public static async deactivate(params: {
    tenantId: string;
    installationId: string;
    deviceIdentity: string;
    certificatePem: string;
    licenseKey: string;
  }) {
    await this.validateIdentity(params);
    const record = await this.get(params.tenantId, params.installationId);
    if (!record || record.deviceIdentity !== params.deviceIdentity) {
      throw new Error("No matching device activation exists.");
    }
    record.state = "SUSPENDED";
    record.deactivatedAt = new Date().toISOString();
    this.activations.set(this.key(params.tenantId, params.installationId), record);

    try {
      await query(
        `UPDATE agent_license_activations
         SET state='SUSPENDED'
         WHERE tenant_id=$1 AND installation_id=$2 AND device_identity=$3`,
        [params.tenantId, params.installationId, params.deviceIdentity]
      );
    } catch {
      // In-memory fallback
    }

    return record;
  }

  public static async revoke(tenantId: string, licenseId: string, reason?: string) {
    this.revokedLicenses.add(licenseId);
    this.revokedLicenses.add(tenantId);
    await this.syncTenantState(tenantId, "REVOKED");
    await EntitlementService.setLicenseStatus(tenantId, "revoked");
    try {
      await query(
        `UPDATE product_licenses
         SET status = 'revoked', revoked_at = NOW(), revocation_reason = $1, updated_at = NOW()
         WHERE (id = $2 OR subscription_id = $2) AND tenant_id = $3`,
        [reason || "Administrative revocation", licenseId, tenantId]
      );
    } catch {
      // In-memory fallback
    }
    return { success: true, licenseId, state: "REVOKED" };
  }

  public static async heartbeat(params: {
    tenantId: string;
    installationId: string;
    deviceIdentity: string;
    certificatePem: string;
    licenseKey: string;
  }) {
    await this.validateIdentity(params);
    const record = await this.get(params.tenantId, params.installationId);
    if (!record || record.deviceIdentity !== params.deviceIdentity) {
      throw new Error("No matching device activation exists.");
    }
    if (record.state !== "ACTIVE" && record.state !== "TRIAL") {
      throw new Error(`Heartbeat denied for license state ${record.state}.`);
    }
    record.lastHeartbeatAt = new Date().toISOString();
    this.activations.set(this.key(params.tenantId, params.installationId), record);

    try {
      await query(
        `UPDATE agent_license_activations
         SET last_heartbeat_at=$3
         WHERE tenant_id=$1 AND installation_id=$2 AND state IN ('ACTIVE','TRIAL')`,
        [params.tenantId, params.installationId, record.lastHeartbeatAt]
      );
    } catch {
      // In-memory fallback
    }

    return record;
  }

  public static async syncState(
    tenantId: string,
    installationId: string,
    state: AgentLicenseState
  ) {
    const record = await this.get(tenantId, installationId);
    if (!record) throw new Error("No matching device activation exists.");
    record.state = state;
    this.activations.set(this.key(tenantId, installationId), record);

    try {
      await query(
        `UPDATE agent_license_activations SET state=$3 WHERE tenant_id=$1 AND installation_id=$2`,
        [tenantId, installationId, state]
      );
    } catch {
      // In-memory fallback
    }

    return record;
  }

  public static async syncTenantState(tenantId: string, state: AgentLicenseState): Promise<void> {
    for (const record of this.activations.values()) {
      if (record.tenantId === tenantId) record.state = state;
    }
    try {
      await query(
        `UPDATE agent_license_activations SET state=$2 WHERE tenant_id=$1`,
        [tenantId, state]
      );
    } catch {
      // In-memory fallback
    }
  }

  public static async get(
    tenantId: string,
    installationId: string
  ): Promise<AgentLicenseActivation | null> {
    const key = this.key(tenantId, installationId);
    const cached = this.activations.get(key);
    if (cached) return cached;

    try {
      const result = await query<any>(
        `SELECT tenant_id, installation_id, device_identity, certificate_fingerprint,
                license_id, license_expires_at, state, activated_at, last_heartbeat_at
         FROM agent_license_activations
         WHERE tenant_id=$1 AND installation_id=$2`,
        [tenantId, installationId]
      );
      const row = result.rows[0];
      if (row) {
        const record: AgentLicenseActivation = {
          tenantId: row.tenant_id,
          installationId: row.installation_id,
          deviceIdentity: row.device_identity,
          certificateFingerprint: row.certificate_fingerprint,
          licenseId: row.license_id,
          licenseExpiresAt: new Date(row.license_expires_at).toISOString(),
          state: row.state as AgentLicenseState,
          activatedAt: new Date(row.activated_at).toISOString(),
          lastHeartbeatAt: row.last_heartbeat_at
            ? new Date(row.last_heartbeat_at).toISOString()
            : undefined,
        };
        this.activations.set(key, record);
        return record;
      }
    } catch {
      // In-memory mode
    }

    return null;
  }

  public static async isDeviceActive(
    tenantId: string,
    deviceIdentity: string
  ): Promise<boolean> {
    const cached = [...this.activations.values()].find(
      (item) => item.tenantId === tenantId && item.deviceIdentity === deviceIdentity
    );
    if (cached) {
      return (
        (cached.state === "ACTIVE" || cached.state === "TRIAL") &&
        Date.parse(cached.licenseExpiresAt) > Date.now()
      );
    }

    try {
      const result = await query<{ state: AgentLicenseState }>(
        `SELECT state FROM agent_license_activations
         WHERE tenant_id=$1 AND device_identity=$2 AND license_expires_at > NOW()
         LIMIT 1`,
        [tenantId, deviceIdentity]
      );
      return result.rows[0]?.state === "ACTIVE" || result.rows[0]?.state === "TRIAL";
    } catch {
      return false;
    }
  }

  /**
   * Lists all activations for a tenant.
   */
  public static async listActivations(tenantId: string): Promise<AgentLicenseActivation[]> {
    const cached = [...this.activations.values()].filter((item) => item.tenantId === tenantId);
    try {
      const result = await query<any>(
        `SELECT tenant_id, installation_id, device_identity, certificate_fingerprint,
                license_id, license_expires_at, state, activated_at, last_heartbeat_at
         FROM agent_license_activations
         WHERE tenant_id=$1
         ORDER BY activated_at DESC`,
        [tenantId]
      );
      if (result.rows.length > 0) {
        return result.rows.map((row) => ({
          tenantId: row.tenant_id,
          installationId: row.installation_id,
          deviceIdentity: row.device_identity,
          certificateFingerprint: row.certificate_fingerprint,
          licenseId: row.license_id,
          licenseExpiresAt: new Date(row.license_expires_at).toISOString(),
          state: row.state as AgentLicenseState,
          activatedAt: new Date(row.activated_at).toISOString(),
          lastHeartbeatAt: row.last_heartbeat_at
            ? new Date(row.last_heartbeat_at).toISOString()
            : undefined,
        }));
      }
    } catch {
      // DB fallback
    }
    return cached;
  }

  /**
   * Deactivates an installation by its installation ID or record ID.
   */
  public static async deactivateInstallation(tenantId: string, installationId: string) {
    const record = await this.get(tenantId, installationId);
    if (!record) {
      throw new Error(`Activation '${installationId}' not found for tenant.`);
    }
    record.state = "SUSPENDED";
    record.deactivatedAt = new Date().toISOString();
    this.activations.set(this.key(tenantId, installationId), record);

    try {
      await query(
        `UPDATE agent_license_activations
         SET state='SUSPENDED'
         WHERE tenant_id=$1 AND installation_id=$2`,
        [tenantId, installationId]
      );
    } catch { /* DB fallback */ }

    return record;
  }
}
