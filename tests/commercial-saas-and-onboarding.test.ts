import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  issueCommercialLicense,
  verifyCommercialLicense,
} from "../src/lib/billing/licenses";
import {
  evaluateQuotaStatus,
  getTenantSubscription,
} from "../src/lib/billing/plans";
import {
  recordUsageMetric,
  getTenantUsageReport,
  resetUsageMetrics,
} from "../src/lib/billing/metering";
import {
  getOnboardingState,
  advanceOnboardingStep,
  generateAgentInstallCommand,
  generateCanaryDetection,
} from "../src/lib/onboarding/goldenPath";

test("ShieldDesk Phase 6: Commercial SaaS, Licensing, Quotas & Onboarding Golden Path", async (t) => {
  await t.test("Cryptographic Commercial License: Issue, Verify, and Tamper Rejection", () => {
    const futureExpiry = new Date(Date.now() + 365 * 86400 * 1000).toISOString();
    const pastExpiry = new Date(Date.now() - 86400 * 1000).toISOString();

    // 1. Issue valid license
    const license = issueCommercialLicense({
      tenantId: "acme-tenant",
      tier: "enterprise",
      maxEndpoints: 5000,
      maxUsers: 100,
      features: ["dual_approval", "sso_scim", "custom_playbooks", "mtls"],
      expiresAt: futureExpiry,
    });

    assert.ok(license.rawLicense.includes("."), "Raw license must be token.signature format");

    // 2. Verify valid license
    const verifyValid = verifyCommercialLicense(license.rawLicense);
    assert.equal(verifyValid.valid, true);
    assert.equal(verifyValid.payload?.tenantId, "acme-tenant");
    assert.equal(verifyValid.payload?.tier, "enterprise");
    assert.equal(verifyValid.payload?.maxEndpoints, 5000);

    // 3. Reject tampered license payload
    const [payloadB64, sig] = license.rawLicense.split(".");
    const decodedJson = Buffer.from(payloadB64, "base64url").toString("utf8");
    const tamperedJson = decodedJson.replace("5000", "999999"); // Attacker inflated endpoints
    const tamperedPayloadB64 = Buffer.from(tamperedJson, "utf8").toString("base64url");
    const tamperedLicense = `${tamperedPayloadB64}.${sig}`;

    const verifyTampered = verifyCommercialLicense(tamperedLicense);
    assert.equal(verifyTampered.valid, false);
    assert.match(verifyTampered.reason || "", /signature verification failed/i);

    // 4. Reject expired license
    const expiredLicense = issueCommercialLicense({
      tenantId: "acme-tenant",
      tier: "professional",
      maxEndpoints: 100,
      maxUsers: 10,
      features: ["automated_remediation"],
      expiresAt: pastExpiry,
    });

    const verifyExpired = verifyCommercialLicense(expiredLicense.rawLicense);
    assert.equal(verifyExpired.valid, false);
    assert.match(verifyExpired.reason || "", /expired/i);
  });

  await t.test("Over-Quota Enforcement: Soft Warning, Grace Period, Hard Block & Telemetry Invariant", async () => {
    // Acme is on Professional (100 endpoints)
    // 1. Normal: 50/100 (50%)
    const normalEval = await evaluateQuotaStatus("acme-tenant", 50);
    assert.equal(normalEval.status, "normal");
    assert.equal(normalEval.canEnroll, true);
    assert.equal(normalEval.canIngestTelemetry, true);

    // 2. Soft Warning: 90/100 (90%)
    const warningEval = await evaluateQuotaStatus("acme-tenant", 90);
    assert.equal(warningEval.status, "warning");
    assert.equal(warningEval.canEnroll, true);
    assert.equal(warningEval.canIngestTelemetry, true);
    assert.match(warningEval.message, /Approaching plan endpoint limit/);

    // 3. Grace Period: 100/100 (100%)
    const graceEval = await evaluateQuotaStatus("acme-tenant", 100);
    assert.equal(graceEval.status, "grace_period");
    assert.equal(graceEval.canEnroll, true, "Grace period permits enrollment up to 110%");
    assert.equal(graceEval.canIngestTelemetry, true);
    assert.match(graceEval.message, /active grace period/);

    // 4. Hard Block: 110/100 (110%)
    const blockedEval = await evaluateQuotaStatus("acme-tenant", 110);
    assert.equal(blockedEval.status, "blocked");
    assert.equal(blockedEval.canEnroll, false, "Must block new enrollments at 110%");
    assert.equal(blockedEval.canIngestTelemetry, true, "Critical invariant: NEVER drop telemetry or kill agents");
    assert.match(blockedEval.message, /temporarily blocked/);
  });

  await t.test("Usage Metering: Endpoints, Telemetry, Remediations & AI Tokens", () => {
    resetUsageMetrics();

    // Record various metrics for tenant
    recordUsageMetric("acme-tenant", "active_endpoints", 42);
    recordUsageMetric("acme-tenant", "telemetry_bytes", 1024 * 1024 * 50); // 50 MB
    recordUsageMetric("acme-tenant", "remediations_executed", 3);
    recordUsageMetric("acme-tenant", "ai_tokens_consumed", 15400);

    const report = getTenantUsageReport("acme-tenant");
    assert.equal(report.activeEndpoints, 42);
    assert.equal(report.telemetryBytes, 1024 * 1024 * 50);
    assert.equal(report.remediationsExecuted, 3);
    assert.equal(report.aiTokensConsumed, 15400);
  });

  await t.test("Customer Onboarding Golden Path: 15-Minute Milestones & Canary Simulation", () => {
    const tenantId = "onboarding-new-tenant";

    // 1. Initial State
    const initial = getOnboardingState(tenantId);
    assert.equal(initial.currentStep, "SIGNUP");
    assert.equal(initial.completedAt, null);

    // 2. Generate install command for Linux & Windows
    const linuxCmd = generateAgentInstallCommand({
      controlUrl: "https://shielddesk.acme.corp",
      enrollToken: "sdt_demo_token_123",
      osType: "linux",
    });
    assert.ok(linuxCmd.startsWith("curl -sSL"));
    assert.ok(linuxCmd.includes("sdt_demo_token_123"));

    const winCmd = generateAgentInstallCommand({
      controlUrl: "https://shielddesk.acme.corp",
      enrollToken: "sdt_demo_token_123",
      osType: "windows",
    });
    assert.ok(winCmd.includes("Initialize-ShieldDeskAgent"));

    // 3. Advance through milestones
    advanceOnboardingStep(tenantId, "SIGNUP");
    advanceOnboardingStep(tenantId, "ORGANIZATION_CREATED");
    advanceOnboardingStep(tenantId, "ENROLLMENT_TOKEN_ISSUED");
    advanceOnboardingStep(tenantId, "INSTALLATION_COMMAND_GENERATED");
    advanceOnboardingStep(tenantId, "FIRST_AGENT_CONNECTED");

    // 4. Trigger Canary Detection
    const canary = generateCanaryDetection(tenantId);
    assert.ok(canary.incidentId);
    assert.equal(canary.recommendedAction, "file.quarantine");

    // 5. Complete Golden Path
    advanceOnboardingStep(tenantId, "INCIDENT_SURFACED");
    const finalState = advanceOnboardingStep(tenantId, "FIRST_REMEDIATION_VERIFIED");

    assert.equal(finalState.currentStep, "FIRST_REMEDIATION_VERIFIED");
    assert.ok(finalState.completedAt);
    assert.ok(finalState.timeToFirstRemediationMinutes !== undefined);
    assert.ok(finalState.timeToFirstRemediationMinutes >= 1);
  });
});
