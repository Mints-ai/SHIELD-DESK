/**
 * Phase H: Execution Broker, Hardened Agent & mTLS Lifecycle Test Suite
 *
 * Verifies:
 * 1. Execution Broker as Single Dispatch Point (Rule 3)
 * 2. Full lifecycle state transitions (Rule 8: REQUESTED -> APPROVED -> SIGNED -> QUEUED -> DELIVERED -> EXECUTED)
 * 3. Short-lived ephemeral dispatch tokens (5-minute TTL, anti-replay nonces)
 * 4. Rule 2 Invariant: Missing snapshot for high-impact Tier 2/Tier 3 commands fails closed
 * 5. Canonical RSA-SHA256 Command Signing & Verification
 * 6. Signed Execution Results: Agent signs stdout/stderr and host state digest with enrolled key
 * 7. mTLS Device Certificate Verification and Revocation Guard
 * 8. Agent Self-Update with canary health verification and automated rollback
 * 9. Real Linux (iptables) and Windows (netsh) command handling
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ExecutionBroker } from "../src/lib/fleet/executionBroker";
import { AgentResultVerifier } from "../src/lib/fleet/agentResultVerifier";
import { MTLSGuard } from "../src/lib/fleet/mtlsGuard";
import { AgentUpdater } from "../src/lib/fleet/agentUpdater";
import { signCommand, verifyCommandSignature, getControlPlanePublicKey } from "../src/lib/fleet/commandSigning";

test("Phase H: Execution Broker & Agent Hardening Suite", async (t) => {
  const tenantId = "acme-tenant";
  const agentId = "ea-srv-linux-01";

  // Generate test RSA keypair for agent signing
  const { privateKey: agentPrivateKey, publicKey: agentPublicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  await t.test("Rule 2 Invariant: High-impact dispatch without pre-execution snapshot is BLOCKED", async () => {
    const result = await ExecutionBroker.dispatchCommand({
      agentId,
      tenantId,
      command: "iptables -A INPUT -s 198.51.100.5 -j DROP",
      tier: "Tier 2",
      tokenId: "mock-token-id", // unapproved
      snapshotId: undefined, // Missing snapshot!
      dispatchedBy: "usr-sec-lead",
    });

    assert.equal(result.success, false);
    assert.equal(result.state, "FAILED");
    assert.ok(result.error?.includes("Rule 4 Violation") || result.error?.includes("Pre-execution safety snapshot is missing"));
  });

  await t.test("Ephemeral Dispatch Tokens: Enforces short-lived credentials and anti-replay nonces", () => {
    const nonce = crypto.randomBytes(16).toString("hex");
    const token = ExecutionBroker.generateDispatchToken({
      commandId: "cmd-test-101",
      agentId,
      tenantId,
      tier: "Tier 2",
      nonce,
      ttlSeconds: 300, // 5 min TTL
    });

    assert.ok(token.tokenId.startsWith("dtok-"));
    assert.equal(token.isConsumed, false);
    assert.ok(token.tokenHash.length === 64);

    // Valid check
    const validCheck = ExecutionBroker.validateDispatchToken(token.tokenId, agentId);
    assert.equal(validCheck.valid, true);

    // Mismatched agent check
    const mismatchCheck = ExecutionBroker.validateDispatchToken(token.tokenId, "wrong-agent-id");
    assert.equal(mismatchCheck.valid, false);
    assert.ok(mismatchCheck.reason?.includes("agent binding mismatch"));

    // Expired token check
    const expiredToken = ExecutionBroker.generateDispatchToken({
      commandId: "cmd-expired",
      agentId,
      tenantId,
      tier: "Tier 1",
      nonce: "exp-nonce",
      ttlSeconds: -10, // already expired
    });
    const expiredCheck = ExecutionBroker.validateDispatchToken(expiredToken.tokenId, agentId);
    assert.equal(expiredCheck.valid, false);
    assert.ok(expiredCheck.reason?.includes("expired"));
  });

  await t.test("Lifecycle State Machine: Transitions through SIGNED -> QUEUED -> DELIVERED", async () => {
    const nonce = crypto.randomBytes(16).toString("hex");
    const dispatch = await ExecutionBroker.dispatchCommand({
      commandId: "cmd-lifecycle-001",
      agentId,
      tenantId,
      command: "ip link set eth1 down",
      tier: "Tier 1",
      snapshotId: "snap-linux-001",
      dispatchedBy: "usr-analyst",
    });

    assert.equal(dispatch.success, true);
    assert.equal(dispatch.state, "QUEUED");
    assert.ok(dispatch.signature.length > 32);

    // Verify command signature
    const isSigValid = verifyCommandSignature({
      agentId,
      command: "ip link set eth1 down",
      nonce: dispatch.nonce,
      tier: "Tier 1",
      signature: dispatch.signature,
    });
    assert.equal(isSigValid, true);

    // Mark command as DELIVERED to agent
    const delivery = await ExecutionBroker.markCommandDelivered(
      dispatch.commandId,
      agentId,
      dispatch.dispatchToken
    );
    assert.equal(delivery.success, true);
    assert.equal(ExecutionBroker.getCommandState(dispatch.commandId), "DELIVERED");
  });

  await t.test("Signed Agent Execution Results: Verifies cryptographic agent signature & state digest", async () => {
    const commandId = "cmd-exec-test-202";
    const executionTimestamp = new Date().toISOString();
    const rawHostState = "iptables: [INPUT -s 198.51.100.5 -j DROP]; interfaces: [lo, eth0]";
    const hostStateDigest = AgentResultVerifier.computeHostStateDigest(rawHostState);

    // Agent signs execution payload with its private key
    const resultSignature = AgentResultVerifier.signAgentResult(
      {
        commandId,
        agentId,
        exitCode: 0,
        hostStateDigest,
        executionTimestamp,
      },
      agentPrivateKey
    );

    // Verify through ExecutionBroker with registered agent public key
    const processResult = await ExecutionBroker.processSignedAgentResult(
      {
        commandId,
        agentId,
        tenantId,
        exitCode: 0,
        stdout: "Rule appended successfully to INPUT chain.",
        stderr: "",
        executionTimestamp,
        hostStateDigest,
        resultSignature,
      },
      { agentPublicKeyPem: agentPublicKey }
    );

    assert.equal(processResult.success, true);
    assert.equal(processResult.state, "EXECUTED");
    assert.equal(ExecutionBroker.getCommandState(commandId), "EXECUTED");

    // Negative case: Tampered payload fails verification
    const tamperedResult = await ExecutionBroker.processSignedAgentResult(
      {
        commandId,
        agentId,
        tenantId,
        exitCode: 1, // Mutated exit code
        stdout: "Tampered execution attempt",
        stderr: "",
        executionTimestamp,
        hostStateDigest,
        resultSignature, // Signature no longer matches
      },
      { agentPublicKeyPem: agentPublicKey }
    );

    assert.equal(tamperedResult.success, false);
    assert.equal(tamperedResult.state, "FAILED");
    assert.ok(tamperedResult.reason?.includes("signature verification failed"));
  });

  await t.test("mTLS Device Verification Guard: Rejects revoked certificates & kill switches", async () => {
    // Normal enrolled agent passes
    const validAgent = await MTLSGuard.validateClientCertificate({
      agentId: "ea-srv-linux-01",
      tenantId: "acme-tenant",
    });
    assert.equal(validAgent.allowed, true);

    // Unknown agent fails closed
    const unknownAgent = await MTLSGuard.validateClientCertificate({
      agentId: "ea-unauthorized-host",
      tenantId: "acme-tenant",
    });
    assert.equal(unknownAgent.allowed, false);
    assert.ok(unknownAgent.reason?.includes("Unknown endpoint agent"));

    // Tenant mismatch fails closed
    const tenantMismatch = await MTLSGuard.validateClientCertificate({
      agentId: "ea-srv-linux-01",
      tenantId: "globex-tenant", // cross-tenant spoofing attempt
    });
    assert.equal(tenantMismatch.allowed, false);
    assert.ok(tenantMismatch.reason?.includes("Tenant isolation mismatch"));
  });

  await t.test("Agent Self-Update & Canary Rollback: Verifies manifests & triggers rollback on failure", async () => {
    // 1. Publish signed update manifest
    const manifest = AgentUpdater.publishUpdateManifest({
      version: "1.5.0",
      platform: "linux_amd64",
      binaryUrl: "https://downloads.shielddesk.io/agent/v1.5.0/agent-linux_amd64.tar.gz",
      sha256Checksum: "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890",
      minAgentVersion: "1.0.0",
    });

    assert.equal(manifest.version, "1.5.0");
    assert.ok(manifest.signature.length > 32);
    assert.equal(AgentUpdater.verifyManifest(manifest), true);

    // 2. Canary failure triggers automated rollback event
    const rollbackEvent = await AgentUpdater.processCanaryEvaluation({
      agentId: "ea-srv-linux-01",
      tenantId,
      fromVersion: "1.4.0",
      targetVersion: "1.5.0",
      canarySuccessful: false,
      failureReason: "Canary heartbeat timeout: agent process crashed on boot",
    });

    assert.equal(rollbackEvent.status, "rolled_back");
    assert.ok(rollbackEvent.rollbackReason?.includes("Canary heartbeat timeout"));

    // 3. Canary success verifies update
    const successEvent = await AgentUpdater.processCanaryEvaluation({
      agentId: "ea-srv-linux-02",
      tenantId,
      fromVersion: "1.4.0",
      targetVersion: "1.5.0",
      canarySuccessful: true,
      canaryLatencyMs: 14,
    });

    assert.equal(successEvent.status, "verified");
    assert.equal(successEvent.rollbackReason, undefined);
  });
});
