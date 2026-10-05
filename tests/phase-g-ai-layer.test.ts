/**
 * Phase G: AI Layer, Governance & Evaluation Lab Test Suite
 *
 * Verifies:
 * 1. LLM Gateway & Provider Independence: Local-first Ollama default, pluggable providers.
 * 2. Rule 1 & 2: Structured-output proposals only. Direct execution is strictly forbidden.
 * 3. Rule 5: Proposer cannot approve. AI agents cannot self-approve or execute human approvals.
 * 4. Agent Permissions: Per-agent identity, scoping, and authorization checks.
 * 5. Prompt & Model Versioning: SHA-256 prompt hashing and integrity verification.
 * 6. Evidence Citations: Verification of citations against Evidence Engine & hallucination scoring.
 * 7. AI Evaluation Lab: Permanent benchmark dataset execution, hallucination rate, remediation accuracy, and tool-call error tracking.
 * 8. Tool Router: Enforces tool allow-list, tenant scoping, and blocks unauthorized mutations.
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  LLMGateway,
  PromptRegistry,
  AgentIdentityService,
  EvidenceCitationValidator,
  ToolRouter,
  AIEvaluationLab,
  PERMANENT_BENCHMARK_CASES,
} from "../src/lib/ai";
import { EvidenceEngine } from "../src/lib/decision-engine/evidenceEngine";

test("Phase G: AI Layer & Governance Suite", async (t) => {
  const tenantId = "tenant-cyber-ops";

  await t.test("LLM Gateway: Dispatches structured investigation and enforces schema validation", async () => {
    const untrustedTelemetry = [
      "Process svchost.exe spawned powershell.exe with -enc argument",
      "Network connection to 198.51.100.23:4444 established",
    ];

    const investigation = await LLMGateway.investigateIncident(
      "Suspected Cobalt Strike Beaconing",
      untrustedTelemetry,
      {
        tenantId,
        actorId: "usr-analyst-01",
        provider: "mock",
        promptVersion: "1.0.0",
      }
    );

    assert.ok(investigation.analysis.length > 0);
    assert.ok(["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(investigation.severity));
    assert.ok(investigation.confidence >= 0 && investigation.confidence <= 1.0);
    assert.ok(investigation.recommended_actions.length > 0);
    assert.equal(investigation.modelAttribution?.provider, "mock");
  });

  await t.test("Rule 1 & 2: Remediation proposals are strictly non-executable proposals requiring human sign-off", async () => {
    const evidence = EvidenceEngine.createEvidence("cve_finding", "vuln_scanner", {
      cveId: "CVE-2024-3400",
      targetAsset: "endpoint-wkst-01",
    });
    assert.ok(evidence.id);

    const proposal = await LLMGateway.proposeRemediation(
      "inc-4001",
      "PAN-OS Gateway Command Injection (CVE-2024-3400)",
      [
        {
          evidenceId: evidence.id,
          source: "evidence_engine",
          claim: "Observed active vulnerability CVE-2024-3400 on perimeter firewall",
          verified: true,
          confidence: 0.98,
        },
      ],
      {
        tenantId,
        actorId: "usr-analyst-01",
        agentIdentityId: "ai-agent-triage-default",
        provider: "mock",
      }
    );

    assert.ok(proposal.proposalId.startsWith("prop-"));
    assert.equal(proposal.isExecutable, false, "AI proposal must NEVER be marked executable");
    assert.equal(proposal.requiresHumanApproval, true, "AI proposal must require human sign-off");
    assert.equal(proposal.proposerAgentId, "ai-agent-triage-default");
    assert.ok(proposal.actions.length > 0);
  });

  await t.test("Rule 5 Invariant: Proposer cannot approve own action, and AI agents cannot approve", () => {
    // 1. Proposer === Approver must fail closed
    assert.throws(
      () => {
        AgentIdentityService.assertSeparationOfDuties("usr-analyst-01", "usr-analyst-01", false);
      },
      /Rule 5 Violation: Separation of duties failure/
    );

    // 2. Different human approver passes
    assert.doesNotThrow(() => {
      AgentIdentityService.assertSeparationOfDuties("usr-analyst-01", "usr-lead-responder", false);
    });

    // 3. AI Agent attempting human approval must fail closed
    assert.throws(
      () => {
        AgentIdentityService.assertSeparationOfDuties("usr-analyst-01", "ai-agent-triage-default", true);
      },
      /Rule 5 Violation: AI agent .* cannot perform human approval/
    );
  });

  await t.test("Agent Identity: Validates permitted scopes and blocks unauthorized capabilities", async () => {
    const customAgent = await AgentIdentityService.registerAgent({
      id: "ai-agent-read-only",
      tenantId,
      name: "Read Only Threat Intelligence Agent",
      allowedScopes: ["tools:read", "twin:query"],
      maxRiskTier: "Tier 1",
    });

    assert.equal(customAgent.cannotApprove, true);

    // Permitted scope
    assert.doesNotThrow(() => {
      AgentIdentityService.assertAgentScope(customAgent, "twin:query");
    });

    // Unauthorized scope throws permission denied
    assert.throws(
      () => {
        AgentIdentityService.assertAgentScope(customAgent, "remediation:suggest");
      },
      /AI Agent Permission Denied: Agent 'ai-agent-read-only' lacks required scope/
    );
  });

  await t.test("Prompt Registry: Tracks versions, computes SHA-256 hashes, and detects prompt tampering", async () => {
    const prompt = await PromptRegistry.registerPrompt({
      promptName: "custom_containment_analyzer",
      version: "1.2.0",
      provider: "ollama",
      modelName: "qwen3:4b",
      systemPrompt: "You are an autonomous containment reviewer.",
      userTemplate: "Review incident: {{incidentId}}",
      temperature: 0.05,
    });

    assert.ok(prompt.sha256Hash.length === 64);
    assert.equal(PromptRegistry.verifyIntegrity(prompt), true);

    // Tampered prompt definition fails integrity verification
    const tampered = { ...prompt, systemPrompt: "You are an untrusted malicious reviewer." };
    assert.equal(PromptRegistry.verifyIntegrity(tampered), false);
  });

  await t.test("Evidence Citations: Validates real vs fabricated evidence and calculates hallucination score", () => {
    const realEv = EvidenceEngine.createEvidence("cve_match", "nvd", { cveId: "CVE-2021-44228" });
    assert.ok(realEv.id);

    // Valid citation
    const validCheck = EvidenceCitationValidator.validateCitations(
      [
        {
          evidenceId: realEv.id,
          source: "evidence_engine",
          claim: "Log4j RCE vulnerability detected",
          verified: true,
          confidence: 1.0,
        },
      ],
      ["Log4j vulnerability detected on web cluster"]
    );
    assert.equal(validCheck.isValid, true);
    assert.equal(validCheck.hallucinationScore, 0);

    // Fabricated citations (Hallucination)
    const hallucinatedCheck = EvidenceCitationValidator.validateCitations(
      [
        {
          evidenceId: "fabricated-cve-9999-99999",
          source: "hallucination",
          claim: "Invented backdoor exploit",
          verified: false,
          confidence: 0.1,
        },
      ],
      ["Critical backdoor found in system core"],
      { knownEvidenceKeys: [realEv.id] }
    );
    assert.equal(hallucinatedCheck.isValid, false);
    assert.ok(hallucinatedCheck.hallucinationScore > 0.4);
    assert.equal(hallucinatedCheck.invalidCitations.length, 1);
  });

  await t.test("Tool Router: Allows registered query tools and blocks arbitrary or state-mutating actions", async () => {
    ToolRouter.resetMetrics();

    // 1. Authorized query tool
    const twinResult = await ToolRouter.executeTool({
      toolName: "twin_dependency_query",
      arguments: { assetId: "endpoint-wkst-01" },
      agentIdentityId: "ai-agent-triage-default",
      tenantId,
    });
    assert.equal(twinResult.success, true);

    // 2. Unauthorized tool (blocked deterministically)
    const blockedResult = await ToolRouter.executeTool({
      toolName: "reboot_all_servers",
      arguments: { force: true },
      agentIdentityId: "ai-agent-triage-default",
      tenantId,
    });
    assert.equal(blockedResult.success, false);
    assert.equal(blockedResult.errorCode, "TOOL_NOT_FOUND");

    const metrics = ToolRouter.getMetrics();
    assert.equal(metrics.totalCalls, 2);
    assert.equal(metrics.errorCalls, 1);
    assert.equal(metrics.errorRate, 0.5);
  });

  await t.test("AI Evaluation Lab: Runs benchmark dataset and outputs accurate quality metrics", async () => {
    assert.ok(PERMANENT_BENCHMARK_CASES.length >= 5);

    const evalResult = await AIEvaluationLab.runEvaluationSuite({
      tenantId,
      runBy: "usr-sec-analyst",
      provider: "mock",
      modelName: "qwen3:4b",
      promptVersion: "1.0.0",
    });

    assert.ok(evalResult.runId.startsWith("eval-run-"));
    assert.equal(evalResult.totalCases, PERMANENT_BENCHMARK_CASES.length);
    assert.equal(evalResult.passedCases, evalResult.totalCases, "release-gate benchmark must pass every active case");
    assert.equal(evalResult.hallucinationRate, 0, "release-gate benchmark must not accept fabricated evidence");
    assert.equal(evalResult.remediationAccuracy, 1, "release-gate benchmark must match all expected actions");
    assert.equal(evalResult.toolCallErrorRate, 0, "release-gate benchmark must reject unauthorized tools without tool failures");
    assert.ok(evalResult.avgLatencyMs < 5000, "mock-provider benchmark must complete within the deterministic local latency budget");
    assert.ok(typeof evalResult.hallucinationRate === "number");
    assert.ok(typeof evalResult.remediationAccuracy === "number");
    assert.ok(typeof evalResult.toolCallErrorRate === "number");
    assert.ok(evalResult.details.caseResults.length === PERMANENT_BENCHMARK_CASES.length);

    // Past runs retrieval
    const history = await AIEvaluationLab.getEvaluationRuns(tenantId);
    assert.ok(history.length >= 1);
    assert.equal(history[0].tenantId, tenantId);
  });
});
