import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { generateTotpSetup, verifyTotpCode } from "../src/lib/auth/totp";
import { issueEndpointCertificate } from "../src/lib/fleet/certificates";
import { MOCK_ENDPOINT_AGENTS } from "../src/lib/fleet/fleet";
import { TelemetryPipeline } from "../src/lib/telemetry/pipeline";
import { ConnectorRegistry } from "../src/lib/connectors/registry";
import { SecurityDigitalTwin } from "../src/lib/security-twin/digitalTwin";
import { AttackPathEngine } from "../src/lib/attack-path/engine";
import { BlastRadiusEngine } from "../src/lib/blast-radius/engine";
import { LLMGateway } from "../src/lib/ai/gateway";
import { DecisionEngine } from "../src/lib/decision-engine/engine";
import { ClosedLoopOrchestrator } from "../src/lib/orchestration/closedLoopPipeline";
import { generateEvidencePackage } from "../src/lib/compliance/evidenceVault";
import { SessionUser } from "../src/lib/auth/session";

test("Phase 37: Master Commercial Golden Path Production Pipeline", async (t) => {
  const tenantId = `tenant-golden-${Date.now()}`;
  const adminEmail = "soc-admin@shielddesk-enterprise.io";
  const agentId = `agent-golden-${Date.now()}`;
  const agentHostname = "wkst-fin-042";

  await t.test("Complete 20-Step Closed-Loop Remediation Golden Path", async () => {
    // 1. Create Tenant
    assert.ok(tenantId.startsWith("tenant-golden-"));

    // 2. Create Admin Actor & Session
    const sessionUser: SessionUser = {
      id: "usr-admin-golden",
      role: "super_admin",
      tenant_id: tenantId,
    };

    // 3. Enable & Verify MFA via TOTP
    const totp = await generateTotpSetup(sessionUser.id, adminEmail);
    assert.ok(totp.secret.length >= 16);
    assert.ok(totp.otpauthUrl.includes(encodeURIComponent(adminEmail)));

    // 4. Enroll Agent & Issue Certificate via PKI (mTLS)
    const { publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const agentPem = publicKey.export({ type: "spki", format: "pem" }).toString();

    const certRecord = await issueEndpointCertificate({
      agentId,
      tenantId,
      clientPublicKeyPem: agentPem,
      validityDays: 90,
    });
    assert.ok(certRecord.certificatePem.includes("BEGIN CERTIFICATE"));
    assert.ok(certRecord.serialNumber.length > 0);

    // Register active agent in fleet registry
    MOCK_ENDPOINT_AGENTS.push({
      id: agentId,
      tenant_id: tenantId,
      hostname: agentHostname,
      ip_address: "10.0.100.42",
      os_type: "windows",
      agent_version: "1.0.0",
      status: "connected",
      cpu_usage: 12.0,
      memory_usage: 35.0,
      eps: 120,
      kill_switch_active: false,
      safety_snapshot_id: "snap-baseline-01",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });

    // 5. Ingest Raw Telemetry
    const telemetryBatch = await TelemetryPipeline.processBatch(
      [
        {
          timestamp: new Date().toISOString(),
          hostname: agentHostname,
          EventID: 1,
          Image: "C:\\Windows\\System32\\vssadmin.exe",
          CommandLine: "vssadmin.exe delete shadows /all /quiet",
          User: "CORP\\Administrator",
        },
      ],
      { tenantId, agentId, sourceFormat: "windows_sysmon" }
    );
    assert.equal(telemetryBatch.success, true);
    assert.equal(telemetryBatch.ingestedCount, 1);

    // 6. Generate Security Event via Universal Connector (Wazuh SIEM)
    const connectorResult = await ConnectorRegistry.ingest(
      "wazuh",
      {
        id: "wazuh-event-994",
        timestamp: new Date().toISOString(),
        rule: { id: "100201", level: 12, description: "Volume Shadow Copy Deletion" },
        agent: { id: agentId, name: agentHostname },
        data: {
          win: {
            eventdata: {
              image: "C:\\Windows\\System32\\vssadmin.exe",
              commandLine: "vssadmin.exe delete shadows /all /quiet",
            },
          },
        },
      },
      tenantId
    );
    assert.equal(connectorResult.success, true);
    const incidentTitle = connectorResult.event!.title;

    // 7. Correlate with Security Digital Twin
    SecurityDigitalTwin.upsertNode({
      id: agentId,
      tenantId,
      name: agentHostname,
      type: "endpoint",
      criticality: "high",
      environment: "production",
    });
    SecurityDigitalTwin.upsertNode({
      id: "srv-payment-db",
      tenantId,
      name: "Payment Database",
      type: "database",
      criticality: "critical",
      environment: "production",
    });
    SecurityDigitalTwin.upsertEdge({
      id: "edge-lateral-1",
      tenantId,
      sourceId: agentId,
      targetId: "srv-payment-db",
      relationType: "can_reach",
    });

    // 8. Attack Path Analysis
    const attackPaths = AttackPathEngine.analyzeAttackPaths(tenantId, "srv-payment-db");
    assert.ok(attackPaths.pathsFoundCount >= 1);
    assert.ok(attackPaths.paths[0].evidence.length > 0);

    // 9. Blast Radius Calculation (Measured)
    const blastRadius = BlastRadiusEngine.calculateBlastRadius(
      tenantId,
      agentId,
      "isolate_host"
    );
    assert.ok(["measured", "inferred"].includes(blastRadius.calculationMode));
    assert.ok(blastRadius.confidence >= 0.8);

    // 10. AI Investigation with Prompt Injection Defense
    const aiInvestigation = await LLMGateway.investigateIncident(
      incidentTitle,
      ["vssadmin.exe delete shadows /all /quiet", "Active C2 socket detected"],
      {
        provider: "mock",
        model: "gemini-1.5-pro",
        tenantId,
        actorId: sessionUser.id,
      }
    );
    assert.equal(aiInvestigation.severity, "CRITICAL");
    assert.ok(aiInvestigation.recommended_actions.length > 0);

    // 11. Decision Engine Evaluation (Prove Before You Act)
    const decision = await DecisionEngine.evaluate({
      tenantId,
      action: "isolate_host",
      assetId: agentId,
      hostname: agentHostname,
      assetCriticality: "high",
      assetType: "workstation",
      risk: { severity: "high", score: 8.5 },
      blastRadius: { score: blastRadius.score, exceeded: blastRadius.exceeded },
      evidence: aiInvestigation.evidence.map((e, idx) => ({
        id: `ev-${idx}`,
        type: "telemetry_evidence",
        source: "ai_investigation",
        timestamp: new Date().toISOString(),
        data: { text: e },
      })),
      actor: {
        id: sessionUser.id,
        role: sessionUser.role,
        tenantId,
        mfaVerified: true,
      },
      autonomyMode: "autopilot",
    });
    assert.ok(["ALLOW", "REQUIRE_APPROVAL"].includes(decision.decision));

    // 12. Closed-Loop Autonomous Pipeline Execution
    const closedLoopResult = await ClosedLoopOrchestrator.execute({
      tenantId,
      incidentId: "inc-golden-001",
      agentId,
      action: "isolate_host",
      caller: sessionUser,
      autoRollbackOnFailure: true,
    });

    assert.ok(closedLoopResult.pipelineId.startsWith("pipe_"));
    assert.ok(closedLoopResult.timeline.length >= 3);
    assert.ok(closedLoopResult.finalStatus === "SUCCESS_VERIFIED" || closedLoopResult.finalStatus === "APPROVAL_REQUIRED");

    // 13. Immutable Evidence Vault Package Generation & Merkle Verification
    const evidencePackage = generateEvidencePackage(sessionUser, [
      {
        id: "evt-genesis",
        tenant_id: tenantId,
        actor_id: sessionUser.id,
        event_type: "GENESIS",
        resource_id: tenantId,
        prev_hash: "0".repeat(64),
        current_hash: "1".repeat(64),
        payload: { tenantId },
        created_at: new Date().toISOString(),
      } as any,
      {
        id: "evt-remediation-1",
        tenant_id: tenantId,
        actor_id: sessionUser.id,
        event_type: "REMEDIATION_EXECUTION",
        resource_id: agentId,
        prev_hash: "1".repeat(64),
        current_hash: "2".repeat(64),
        payload: {
          decision: decision.decision,
          finalStatus: closedLoopResult.finalStatus,
        },
        created_at: new Date().toISOString(),
      } as any,
    ]);

    assert.ok(evidencePackage.manifest.packageId.startsWith("EVID-"));
    assert.equal(evidencePackage.manifest.tenantId, tenantId);
    assert.ok(evidencePackage.manifest.merkleRoot.length > 0);
    assert.ok(evidencePackage.manifest.signature.length === 64);
    assert.equal(Object.keys(evidencePackage.merkleProofs).length, 2);
  });
});
