import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { issueCommercialLicense } from "../src/lib/billing/licenses";
import { issueEndpointCertificate } from "../src/lib/fleet/certificates";
import { MTLSGuard } from "../src/lib/fleet/mtlsGuard";
import { LicenseActivationService, AgentLicenseState } from "../src/lib/licensing/licenseActivation";

test("Dedicated agent license activation binds tenant, installation, device, X.509 certificate and entitlement", async () => {
  const tenantId = `tenant-license-${crypto.randomUUID()}`;
  const deviceIdentity = crypto.randomUUID();
  const installationId = `install-${crypto.randomUUID()}`;
  const cert = await issueEndpointCertificate({ agentId: deviceIdentity, tenantId });
  MTLSGuard.registerAgent({ id: deviceIdentity, tenant_id: tenantId, cert_fingerprint: cert.fingerprintSha256.replaceAll(":", "").toLowerCase() });
  const license = issueCommercialLicense({ tenantId, tier: "professional", maxEndpoints: 20, maxUsers: 10, features: ["endpointFleet"], expiresAt: new Date(Date.now() + 86400000).toISOString() });
  const params = { tenantId, installationId, deviceIdentity, certificatePem: cert.certificatePem, licenseKey: license.rawLicense };

  await assert.rejects(() => LicenseActivationService.activate({ ...params, installationId: "" }), /installationId/);
  const validation = await LicenseActivationService.validate(params);
  assert.equal(validation.valid, true);
  const activated = await LicenseActivationService.activate(params);
  assert.equal(activated.state, "ACTIVE");
  assert.equal(activated.deviceIdentity, deviceIdentity);
  assert.equal(await LicenseActivationService.isDeviceActive(tenantId, deviceIdentity), true);
  const previousExpiry = activated.licenseExpiresAt;
  activated.licenseExpiresAt = new Date(Date.now() - 1000).toISOString();
  assert.equal(await LicenseActivationService.isDeviceActive(tenantId, deviceIdentity), false, "expired commercial license must stop command-time entitlement");
  activated.licenseExpiresAt = previousExpiry;
  await assert.rejects(() => LicenseActivationService.activate({ ...params, deviceIdentity: crypto.randomUUID() }), /certificate rejected|does not match/i);

  const states: AgentLicenseState[] = ["TRIAL", "ACTIVE", "PAST_DUE", "SUSPENDED", "EXPIRED", "REVOKED"];
  for (const state of states) {
    assert.equal((await LicenseActivationService.syncState(tenantId, installationId, state)).state, state);
    assert.equal(await LicenseActivationService.isDeviceActive(tenantId, deviceIdentity), state === "ACTIVE" || state === "TRIAL");
  }
  await assert.rejects(() => LicenseActivationService.heartbeat(params), /Heartbeat denied.*REVOKED/);
  await LicenseActivationService.syncState(tenantId, installationId, "ACTIVE");
  assert.ok((await LicenseActivationService.heartbeat(params)).lastHeartbeatAt);
  assert.equal((await LicenseActivationService.deactivate(params)).state, "SUSPENDED");
});
