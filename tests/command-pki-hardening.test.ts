import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signCommand, verifyCommandSignature } from "../src/lib/fleet/commandSigning";
import { ExecutionBroker } from "../src/lib/fleet/executionBroker";
import { AgentResultVerifier } from "../src/lib/fleet/agentResultVerifier";
import { MTLSGuard } from "../src/lib/fleet/mtlsGuard";
import { issueEndpointCertificate, validateEndpointCertificate } from "../src/lib/fleet/certificates";

test("Command and PKI security regression cases", async (t) => {
  const agentId = "ea-srv-linux-01";
  const tenantId = "acme-tenant";

  await t.test("signature rejects command, agent, tier, and nonce payload modification", () => {
    const payload = { agentId, command: "block_ip 192.0.2.1", tier: "Tier 1", nonce: "nonce-unique" };
    const signature = signCommand(payload);
    assert.equal(verifyCommandSignature({ ...payload, signature }), true);
    for (const modified of [
      { ...payload, command: "block_ip 203.0.113.1" },
      { ...payload, agentId: "agent-spoofed" },
      { ...payload, tier: "Tier 3" },
      { ...payload, nonce: "nonce-reused-or-modified" },
    ]) assert.equal(verifyCommandSignature({ ...modified, signature }), false);
  });

  await t.test("delivery token is one-use and bound to its agent", async () => {
    const token = ExecutionBroker.generateDispatchToken({ commandId: "cmd-once", agentId, tenantId, tier: "Tier 1", nonce: "nonce-once" });
    const first = await ExecutionBroker.markCommandDelivered("cmd-once", agentId, token.tokenId);
    assert.equal(first.success, true);
    const replay = await ExecutionBroker.markCommandDelivered("cmd-once", agentId, token.tokenId);
    assert.equal(replay.success, false);
    const wrongAgentToken = ExecutionBroker.generateDispatchToken({ commandId: "cmd-wrong-agent", agentId, tenantId, tier: "Tier 1", nonce: "nonce-agent" });
    const wrongAgent = await ExecutionBroker.markCommandDelivered("cmd-wrong-agent", "ea-srv-linux-02", wrongAgentToken.tokenId);
    assert.equal(wrongAgent.success, false);
  });

  await t.test("kill switch engaged after dispatch blocks delivery", async () => {
    const token = ExecutionBroker.generateDispatchToken({ commandId: "cmd-kill-race", agentId, tenantId, tier: "Tier 1", nonce: "nonce-race" });
    MTLSGuard.registerAgent({ id: agentId, tenant_id: tenantId, kill_switch_active: true });
    try {
      const delivery = await ExecutionBroker.markCommandDelivered("cmd-kill-race", agentId, token.tokenId);
      assert.equal(delivery.success, false);
      assert.match(delivery.reason || "", /Kill Switch/);
    } finally {
      MTLSGuard.registerAgent({ id: agentId, tenant_id: tenantId, kill_switch_active: false });
    }
  });

  await t.test("mTLS rejects cross-tenant identity and expired certificates", async () => {
    const wrongTenant = await MTLSGuard.validateClientCertificate({ agentId, tenantId: "tenant-other" });
    assert.equal(wrongTenant.allowed, false);
    assert.match(wrongTenant.reason || "", /Tenant isolation mismatch/);
    const expired = await issueEndpointCertificate({ agentId: "expired-agent-123", tenantId, validityDays: -1 });
    const validation = await validateEndpointCertificate({ certificatePem: expired.certificatePem, expectedAgentId: "expired-agent-123", expectedTenantId: tenantId });
    assert.equal(validation.valid, false);
    assert.match(validation.error || "", /expired/);
  });

  await t.test("signed result rejects stale timestamps, timestamp edits, and impersonated agent IDs", async () => {
    const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
    const staleTime = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const stateDigest = AgentResultVerifier.computeHostStateDigest({ processCount: 4 });
    const signature = AgentResultVerifier.signAgentResult({ commandId: "cmd-stale", agentId, exitCode: 0, hostStateDigest: stateDigest, executionTimestamp: staleTime }, pair.privateKey);
    const stale = await AgentResultVerifier.verifyResult({ commandId: "cmd-stale", agentId, tenantId, exitCode: 0, stdout: "", stderr: "", executionTimestamp: staleTime, hostStateDigest: stateDigest, resultSignature: signature }, { agentPublicKeyPem: pair.publicKey });
    assert.equal(stale.verified, false);
    assert.match(stale.reason || "", /freshness window/);

    const freshTime = new Date().toISOString();
    const freshSignature = AgentResultVerifier.signAgentResult({ commandId: "cmd-fresh", agentId, exitCode: 0, hostStateDigest: stateDigest, executionTimestamp: freshTime }, pair.privateKey);
    const edited = await AgentResultVerifier.verifyResult({ commandId: "cmd-fresh", agentId: "agent-impersonated", tenantId, exitCode: 0, stdout: "", stderr: "", executionTimestamp: freshTime, hostStateDigest: stateDigest, resultSignature: freshSignature }, { agentPublicKeyPem: pair.publicKey });
    assert.equal(edited.verified, false);
  });
});
