import "server-only";
import crypto from "node:crypto";
import { query } from "@/lib/db";
import { verifyCommercialLicense } from "@/lib/billing/licenses";
import { validateEndpointCertificate } from "@/lib/fleet/certificates";
import { MTLSGuard } from "@/lib/fleet/mtlsGuard";
import { X509Certificate } from "node:crypto";

export type AgentLicenseState = "TRIAL" | "ACTIVE" | "PAST_DUE" | "SUSPENDED" | "EXPIRED" | "REVOKED";
export interface AgentLicenseActivation {
  tenantId: string;
  installationId: string;
  deviceIdentity: string;
  certificateFingerprint: string;
  licenseId: string;
  state: AgentLicenseState;
  activatedAt: string;
  lastHeartbeatAt?: string;
}

export class LicenseActivationService {
  private static activations = new Map<string, AgentLicenseActivation>();
  private static key(tenantId: string, installationId: string) { return `${tenantId}:${installationId}`; }

  private static async validateIdentity(params: { tenantId: string; installationId: string; deviceIdentity: string; certificatePem: string; licenseKey: string }) {
    for (const [name, value] of Object.entries(params)) if (typeof value !== "string" || !value.trim()) throw new Error(`Missing required activation field '${name}'.`);
    const certificate = await validateEndpointCertificate({ certificatePem: params.certificatePem, expectedAgentId: params.deviceIdentity, expectedTenantId: params.tenantId });
    if (!certificate.valid || !certificate.serialNumber) throw new Error(`Device certificate rejected: ${certificate.error || "identity mismatch"}`);
    const fingerprint = new X509Certificate(params.certificatePem).fingerprint256.replaceAll(":", "").toLowerCase();
    const device = await MTLSGuard.validateClientCertificate({ agentId: params.deviceIdentity, certFingerprint: fingerprint, tenantId: params.tenantId });
    if (!device.allowed) throw new Error(`Device identity rejected: ${device.reason || "mTLS check failed"}`);
    const license = verifyCommercialLicense(params.licenseKey);
    if (!license.valid || !license.payload) throw new Error(`License rejected: ${license.reason || "invalid license"}`);
    if (license.payload.tenantId !== params.tenantId && license.payload.tenantId !== "*") throw new Error("License tenant does not match device tenant.");
    if (!license.payload.features.includes("endpointFleet")) throw new Error("License does not include the endpointFleet entitlement.");
    return { fingerprint, licenseId: license.payload.licenseId, state: license.payload.tier === "community" ? "TRIAL" as const : "ACTIVE" as const };
  }

  public static async validate(params: { tenantId: string; installationId: string; deviceIdentity: string; certificatePem: string; licenseKey: string }) {
    const valid = await this.validateIdentity(params);
    const existing = await this.get(params.tenantId, params.installationId);
    const state = existing?.state || valid.state;
    return { valid: (!existing || existing.deviceIdentity === params.deviceIdentity) && (state === "ACTIVE" || state === "TRIAL"), state, licenseId: valid.licenseId };
  }

  public static async activate(params: { tenantId: string; installationId: string; deviceIdentity: string; certificatePem: string; licenseKey: string }): Promise<AgentLicenseActivation> {
    const identity = await this.validateIdentity(params);
    const key = this.key(params.tenantId, params.installationId);
    const previous = await this.get(params.tenantId, params.installationId);
    if (previous && previous.deviceIdentity !== params.deviceIdentity) throw new Error("Installation is already bound to a different device identity.");
    const record: AgentLicenseActivation = { tenantId: params.tenantId, installationId: params.installationId, deviceIdentity: params.deviceIdentity, certificateFingerprint: identity.fingerprint, licenseId: identity.licenseId, state: identity.state, activatedAt: previous?.activatedAt || new Date().toISOString() };
    this.activations.set(key, record);
    try { await query(`INSERT INTO agent_license_activations (tenant_id, installation_id, device_identity, certificate_fingerprint, license_id, state, activated_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id, installation_id) DO UPDATE SET certificate_fingerprint=EXCLUDED.certificate_fingerprint, license_id=EXCLUDED.license_id, state=EXCLUDED.state`, [record.tenantId, record.installationId, record.deviceIdentity, record.certificateFingerprint, record.licenseId, record.state, record.activatedAt]); } catch { /* in-memory fallback for tests/offline development */ }
    return record;
  }

  public static async deactivate(params: { tenantId: string; installationId: string; deviceIdentity: string; certificatePem: string; licenseKey: string }) {
    await this.validateIdentity(params);
    const record = await this.get(params.tenantId, params.installationId);
    if (!record || record.deviceIdentity !== params.deviceIdentity) throw new Error("No matching device activation exists.");
    record.state = "SUSPENDED";
    this.activations.set(this.key(params.tenantId, params.installationId), record);
    try { await query(`UPDATE agent_license_activations SET state='SUSPENDED' WHERE tenant_id=$1 AND installation_id=$2 AND device_identity=$3`, [params.tenantId, params.installationId, params.deviceIdentity]); } catch { /* in-memory fallback */ }
    return record;
  }

  public static async heartbeat(params: { tenantId: string; installationId: string; deviceIdentity: string; certificatePem: string; licenseKey: string }) {
    await this.validateIdentity(params);
    const record = await this.get(params.tenantId, params.installationId);
    if (!record || record.deviceIdentity !== params.deviceIdentity) throw new Error("No matching device activation exists.");
    if (record.state !== "ACTIVE" && record.state !== "TRIAL") throw new Error(`Heartbeat denied for license state ${record.state}.`);
    record.lastHeartbeatAt = new Date().toISOString();
    this.activations.set(this.key(params.tenantId, params.installationId), record);
    try { await query(`UPDATE agent_license_activations SET last_heartbeat_at=$3 WHERE tenant_id=$1 AND installation_id=$2 AND state IN ('ACTIVE','TRIAL')`, [params.tenantId, params.installationId, record.lastHeartbeatAt]); } catch { /* in-memory fallback */ }
    return record;
  }

  /** Synchronizes a validated billing/license state transition for a bound installation. */
  public static async syncState(tenantId: string, installationId: string, state: AgentLicenseState) {
    const record = await this.get(tenantId, installationId);
    if (!record) throw new Error("No matching device activation exists.");
    record.state = state;
    this.activations.set(this.key(tenantId, installationId), record);
    try { await query(`UPDATE agent_license_activations SET state=$3 WHERE tenant_id=$1 AND installation_id=$2`, [tenantId, installationId, state]); } catch { /* in-memory fallback */ }
    return record;
  }

  public static async syncTenantState(tenantId: string, state: AgentLicenseState): Promise<void> {
    for (const record of this.activations.values()) {
      if (record.tenantId === tenantId) record.state = state;
    }
    try { await query(`UPDATE agent_license_activations SET state=$2 WHERE tenant_id=$1`, [tenantId, state]); } catch { /* in-memory fallback */ }
  }

  public static async get(tenantId: string, installationId: string): Promise<AgentLicenseActivation | null> {
    const key = this.key(tenantId, installationId);
    const cached = this.activations.get(key);
    if (cached) return cached;
    try {
      const result = await query<any>(`SELECT tenant_id, installation_id, device_identity, certificate_fingerprint, license_id, state, activated_at, last_heartbeat_at FROM agent_license_activations WHERE tenant_id=$1 AND installation_id=$2`, [tenantId, installationId]);
      const row = result.rows[0];
      if (row) { const record = { tenantId: row.tenant_id, installationId: row.installation_id, deviceIdentity: row.device_identity, certificateFingerprint: row.certificate_fingerprint, licenseId: row.license_id, state: row.state as AgentLicenseState, activatedAt: new Date(row.activated_at).toISOString(), lastHeartbeatAt: row.last_heartbeat_at ? new Date(row.last_heartbeat_at).toISOString() : undefined }; this.activations.set(key, record); return record; }
    } catch { /* in-memory mode */ }
    return null;
  }

  public static async isDeviceActive(tenantId: string, deviceIdentity: string): Promise<boolean> {
    const cached = [...this.activations.values()].find((item) => item.tenantId === tenantId && item.deviceIdentity === deviceIdentity);
    if (cached) return cached.state === "ACTIVE" || cached.state === "TRIAL";
    try {
      const result = await query<{ state: AgentLicenseState }>(`SELECT state FROM agent_license_activations WHERE tenant_id=$1 AND device_identity=$2 LIMIT 1`, [tenantId, deviceIdentity]);
      return result.rows[0]?.state === "ACTIVE" || result.rows[0]?.state === "TRIAL";
    } catch { return false; }
  }
}
