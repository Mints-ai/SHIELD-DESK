import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { NextRequest } from "next/server";
import {
  issueEndpointCertificate,
  validateEndpointCertificate,
  rotateEndpointCertificate,
  revokeEndpointCertificate,
  getOrCreateControlPlaneCA,
  getRootCACertificatePem,
} from "@/lib/fleet/certificates";
import { createSessionToken } from "@/lib/auth/token";
import { createEnrollmentToken } from "@/lib/fleet/enrollment";
import { POST as enrollPOST } from "@/app/api/agent/enroll/route";
import { GET as fleetCaGET } from "@/app/api/fleet/ca/route";
import { GET as fleetCertificatesGET } from "@/app/api/fleet/certificates/route";
import { POST as revokeCertPOST } from "@/app/api/fleet/certificates/revoke/route";
import { POST as rotateCertPOST } from "@/app/api/agent/certificate/rotate/route";
import { issueCommercialLicense } from "@/lib/billing/licenses";

test("ShieldDesk SD-008 & SD-009: X.509 Certificate Pipeline & Revocation Suite", async (t) => {
  const adminToken = createSessionToken({
    uid: "usr-admin-01",
    tenantId: "acme-tenant",
    role: "system_admin",
  });

  const analystToken = createSessionToken({
    uid: "usr-analyst-01",
    tenantId: "acme-tenant",
    role: "analyst",
  });

  const testAgentId = "ea888888-8888-8888-8888-888888888888";
  const testTenantId = "acme-tenant";

  await t.test("SD-008: Control plane initializes valid Root CA certificate", () => {
    const ca = getOrCreateControlPlaneCA();
    assert.ok(ca.caCertificatePem.includes("-----BEGIN CERTIFICATE-----"));

    const rootCert = new crypto.X509Certificate(ca.caCertificatePem);
    assert.match(rootCert.subject, /CN=ShieldDesk Root CA/);
    assert.match(rootCert.issuer, /CN=ShieldDesk Root CA/); // Self-signed
    assert.strictEqual(rootCert.verify(ca.publicKey), true);
  });

  await t.test("SD-008: Issue valid X.509 client certificate for enrolled agent", async () => {
    const certResult = await issueEndpointCertificate({
      agentId: testAgentId,
      tenantId: testTenantId,
      validityDays: 90,
    });

    assert.ok(certResult.certificatePem.includes("-----BEGIN CERTIFICATE-----"));
    assert.ok(certResult.serialNumber.length > 10);
    assert.ok(certResult.fingerprintSha256.length > 20);

    const x509 = new crypto.X509Certificate(certResult.certificatePem);
    assert.match(x509.subject, /CN=agent-ea888888-8888-8888-8888-888888888888/);
    assert.match(x509.subject, /OU=acme-tenant/);
    assert.match(x509.issuer, /CN=ShieldDesk Root CA/);

    const ca = getOrCreateControlPlaneCA();
    assert.strictEqual(x509.verify(ca.publicKey), true);

    // Validate using validateEndpointCertificate
    const validation = await validateEndpointCertificate({
      certificatePem: certResult.certificatePem,
      expectedAgentId: testAgentId,
      expectedTenantId: testTenantId,
    });
    assert.strictEqual(validation.valid, true);
    assert.strictEqual(validation.agentId, testAgentId);
    assert.strictEqual(validation.tenantId, testTenantId);
  });

  await t.test("SD-008: validateEndpointCertificate rejects mismatched agent or tenant", async () => {
    const certResult = await issueEndpointCertificate({
      agentId: testAgentId,
      tenantId: testTenantId,
    });

    // Mismatched agent
    const badAgent = await validateEndpointCertificate({
      certificatePem: certResult.certificatePem,
      expectedAgentId: "ea999999-9999-9999-9999-999999999999",
      expectedTenantId: testTenantId,
    });
    assert.strictEqual(badAgent.valid, false);
    assert.match(badAgent.error || "", /CN does not match/);

    // Mismatched tenant
    const badTenant = await validateEndpointCertificate({
      certificatePem: certResult.certificatePem,
      expectedAgentId: testAgentId,
      expectedTenantId: "globex-tenant",
    });
    assert.strictEqual(badTenant.valid, false);
    assert.match(badTenant.error || "", /OU does not match/);
  });

  await t.test("SD-009: Rotate active endpoint certificate", async () => {
    const originalCert = await issueEndpointCertificate({
      agentId: testAgentId,
      tenantId: testTenantId,
    });

    const rotated = await rotateEndpointCertificate({
      agentId: testAgentId,
      tenantId: testTenantId,
      currentSerialNumber: originalCert.serialNumber,
    });

    assert.strictEqual(rotated.success, true);
    assert.ok(rotated.newCertificate);
    assert.notStrictEqual(rotated.newCertificate.serialNumber, originalCert.serialNumber);

    // Old certificate should now be revoked (superseded)
    const oldValidation = await validateEndpointCertificate({
      certificatePem: originalCert.certificatePem,
    });
    assert.strictEqual(oldValidation.valid, false);
    assert.match(oldValidation.error || "", /revoked/);

    // New certificate should be valid
    const newValidation = await validateEndpointCertificate({
      certificatePem: rotated.newCertificate.certificatePem,
      expectedAgentId: testAgentId,
      expectedTenantId: testTenantId,
    });
    assert.strictEqual(newValidation.valid, true);
  });

  await t.test("SD-009: Revoke certificate invalidates subsequent mTLS validation", async () => {
    const cert = await issueEndpointCertificate({
      agentId: testAgentId,
      tenantId: testTenantId,
    });

    const revokeRes = await revokeEndpointCertificate({
      serialNumber: cert.serialNumber,
      reason: "Compromised host detected by SecOps",
      revokedBy: "usr-admin-01",
    });
    assert.strictEqual(revokeRes.success, true);

    const val = await validateEndpointCertificate({
      certificatePem: cert.certificatePem,
    });
    assert.strictEqual(val.valid, false);
    assert.match(val.error || "", /revoked/);
  });

  await t.test("SD-008: GET /api/fleet/ca exports Root CA certificate", async () => {
    const res = await fleetCaGET();
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.ok(body.caCertificate.includes("-----BEGIN CERTIFICATE-----"));
    assert.match(body.subject, /ShieldDesk Root CA/);
  });

  await t.test("SD-008: POST /api/agent/enroll returns issued X.509 client certificate", async () => {
    const { rawToken } = await createEnrollmentToken({
      caller: { id: "usr-admin-01", tenant_id: "acme-tenant", role: "system_admin" },
      maxUses: 1,
    });

    const enrollReq = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: rawToken,
        hostname: "SEC-WORKSTATION-08",
        osType: "linux",
        installationId: "install-certificate-test-001",
        licenseKey: issueCommercialLicense({ tenantId: "acme-tenant", tier: "professional", maxEndpoints: 100, maxUsers: 20, features: ["endpointFleet"], expiresAt: new Date(Date.now() + 86400000).toISOString() }).rawLicense,
      }),
    });

    const res = await enrollPOST(enrollReq);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.success, true);
    assert.ok(body.agentId);
    assert.ok(body.certificate);
    assert.ok(body.certificate.certificatePem.includes("-----BEGIN CERTIFICATE-----"));
    assert.ok(body.certificate.serialNumber);
  });

  await t.test("SD-009: POST /api/fleet/certificates/revoke enforces admin authorization", async () => {
    // 1. Non-admin is rejected with 403 Forbidden
    const unauthReq = new NextRequest("http://localhost:3000/api/fleet/certificates/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `shielddesk_session=${analystToken}`,
      },
      body: JSON.stringify({
        serialNumber: "NON-EXISTENT-SERIAL",
      }),
    });

    const unauthRes = await revokeCertPOST(unauthReq);
    assert.strictEqual(unauthRes.status, 403);

    // 2. Admin successfully revokes an existing certificate
    const cert = await issueEndpointCertificate({
      agentId: testAgentId,
      tenantId: testTenantId,
    });

    const adminReq = new NextRequest("http://localhost:3000/api/fleet/certificates/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `shielddesk_session=${adminToken}`,
      },
      body: JSON.stringify({
        serialNumber: cert.serialNumber,
        reason: "Administrative quarantine",
      }),
    });

    const adminRes = await revokeCertPOST(adminReq);
    assert.strictEqual(adminRes.status, 200);
    const body = await adminRes.json();
    assert.strictEqual(body.success, true);
  });

  await t.test("SD-009: GET /api/fleet/certificates lists tenant certificates", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet/certificates", {
      method: "GET",
      headers: {
        Cookie: `shielddesk_session=${adminToken}`,
      },
    });

    const res = await fleetCertificatesGET(req);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.tenantId, "acme-tenant");
    assert.ok(Array.isArray(body.certificates));
    assert.ok(body.total >= 1);
  });
});
