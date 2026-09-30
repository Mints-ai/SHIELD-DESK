import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  CAPABILITY_REGISTRY,
  getCapability,
  listCapabilities,
  validateCapabilitySupport,
} from "../src/lib/fleet/capabilities";
import { executeAgentCommand, getEndpointAgent, MOCK_ENDPOINT_AGENTS } from "../src/lib/fleet/fleet";
import { signCommand, verifyCommandSignature } from "../src/lib/fleet/commandSigning";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Phase 8, 10 & 11: Real Endpoint Agent, Capabilities & Anti-Replay Defense", async (t) => {
  const adminUser: SessionUser = {
    id: "usr-admin-test",
    tenant_id: "acme-tenant",
    role: "system_admin",
  };

  await t.test("Capabilities Registry: contains all 10 core capabilities with required metadata", () => {
    const capabilities = listCapabilities();
    assert.equal(capabilities.length, 10, "Registry must contain exactly 10 production capabilities");

    const expectedCapabilities = [
      "network.isolate",
      "network.restore",
      "process.terminate",
      "process.inspect",
      "snapshot.create",
      "snapshot.restore",
      "patch.apply",
      "service.restart",
      "file.quarantine",
      "firewall.block",
    ];

    for (const name of expectedCapabilities) {
      const cap = CAPABILITY_REGISTRY[name];
      assert.ok(cap, `Capability '${name}' must be registered`);
      assert.ok(cap.supportedOS.length > 0, `Capability '${name}' must declare supported OS list`);
      assert.ok(cap.riskLevel, `Capability '${name}' must declare risk level`);
      assert.ok(cap.requiredPermission, `Capability '${name}' must declare required permission`);
      assert.ok(cap.verificationMethod, `Capability '${name}' must declare verification method`);
      assert.ok(typeof cap.approvalLevel === "number", `Capability '${name}' must declare approval level`);
    }
  });

  await t.test("Capability Resolution: resolves canonical names and legacy aliases", () => {
    assert.equal(getCapability("network.isolate")?.name, "network.isolate");
    assert.equal(getCapability("isolate_host")?.name, "network.isolate");
    assert.equal(getCapability("restore_host")?.name, "network.restore");
    assert.equal(getCapability("kill_process 1234")?.name, "process.terminate");
    assert.equal(getCapability("block_ip 10.0.0.1")?.name, "firewall.block");
    assert.equal(getCapability("take_safety_snapshot")?.name, "snapshot.create");
    assert.equal(getCapability("apply_patch cve-1")?.name, "patch.apply");
    assert.equal(getCapability("unknown_action"), undefined);
  });

  await t.test("OS Compatibility Validation: correctly evaluates OS support", () => {
    // Linux supports network.isolate
    const linuxIsolate = validateCapabilitySupport("network.isolate", "linux");
    assert.equal(linuxIsolate.supported, true);

    // Windows supports network.isolate
    const winIsolate = validateCapabilitySupport("network.isolate", "windows");
    assert.equal(winIsolate.supported, true);

    // Darwin (macOS) does NOT support network.isolate in current registry
    const darwinIsolate = validateCapabilitySupport("network.isolate", "darwin");
    assert.equal(darwinIsolate.supported, false);
    assert.match(darwinIsolate.reason || "", /not supported on target OS 'darwin'/);

    // Darwin DOES support process.terminate
    const darwinProcess = validateCapabilitySupport("process.terminate", "darwin");
    assert.equal(darwinProcess.supported, true);

    // Unknown capability returns supported: false
    const unknown = validateCapabilitySupport("unregistered.capability", "linux");
    assert.equal(unknown.supported, false);
    assert.match(unknown.reason || "", /Unknown capability/);
  });

  await t.test("Capability Enforcement: rejects commands unsupported on target OS in executeAgentCommand", async () => {
    // Register or find a test agent with os_type = "darwin"
    let darwinAgent = MOCK_ENDPOINT_AGENTS.find((a) => a.os_type === "darwin");
    if (!darwinAgent) {
      darwinAgent = {
        id: "ea-darwin-test-01",
        tenant_id: "acme-tenant",
        hostname: "MACBOOK-PRO-01",
        ip_address: "192.168.1.99",
        os_type: "darwin",
        agent_version: "0.4.2",
        status: "connected",
        cpu_usage: 12,
        memory_usage: 45,
        eps: 15,
        kill_switch_active: false,
        safety_snapshot_id: null,
        last_heartbeat: new Date().toISOString(),
        created_at: new Date().toISOString(),
      };
      MOCK_ENDPOINT_AGENTS.push(darwinAgent);
    }

    // Attempting network isolation on macOS must be rejected
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: darwinAgent.id,
          command: "isolate_host",
          tier: "Tier 1",
          caller: adminUser,
        });
      },
      (err: Error) => {
        assert.match(err.message, /CAPABILITY_UNSUPPORTED/);
        assert.match(err.message, /network\.isolate/);
        return true;
      }
    );
  });

  await t.test("Anti-Replay Defense & Cryptographic Integrity: detects tampered nonces and prevents replay", () => {
    const payload = {
      agentId: "FIN-WS-042",
      command: "block_ip 198.51.100.77",
      nonce: "nonce-sec-uuid-1",
      tier: "Tier 1",
    };

    const signature = signCommand(payload);
    assert.ok(signature, "Signature should be generated");

    // 1. Valid signature passes verification
    const isValid = verifyCommandSignature({ ...payload, signature });
    assert.equal(isValid, true, "Signature with original nonce must verify");

    // 2. Modifying nonce invalidates cryptographic signature
    const isReplayedTampered = verifyCommandSignature({
      ...payload,
      nonce: "nonce-sec-uuid-2-tampered",
      signature,
    });
    assert.equal(isReplayedTampered, false, "Modified nonce must break cryptographic signature verification");

    // 3. Simulating agent nonce tracking logic
    const seenNonces = new Set<string>();
    function checkAndRecordNonce(nonce: string): boolean {
      if (seenNonces.has(nonce)) {
        return false; // Replayed!
      }
      seenNonces.add(nonce);
      return true; // Fresh!
    }

    assert.equal(checkAndRecordNonce("nonce-sec-uuid-1"), true, "First execution of nonce should succeed");
    assert.equal(checkAndRecordNonce("nonce-sec-uuid-1"), false, "Second execution of identical nonce must be rejected as replay attack");
  });
});
