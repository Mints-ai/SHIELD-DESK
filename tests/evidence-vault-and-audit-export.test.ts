import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
} from "../src/lib/compliance/merkle";
import {
  verifyHashChainIntegrity,
  generateEvidencePackage,
  computeEventHash,
} from "../src/lib/compliance/evidenceVault";
import type { HashChainAuditRecord } from "../src/lib/fleet/fleet";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Phase 7: SOC 2 & ISO 27001 Cryptographic Evidence Vault", async (t) => {
  const auditorUser: SessionUser = {
    id: "usr-soc2-auditor",
    tenant_id: "acme-tenant",
    role: "analyst",
  };

  await t.test("Merkle Tree & Inclusion Proofs: Computes root and validates inclusion", () => {
    const rawLeaves = [
      "event-head-1",
      "event-head-2",
      "event-head-3",
      "event-head-4",
      "event-head-5",
    ];
    const leafHashes = rawLeaves.map((l) => crypto.createHash("sha256").update(l).digest("hex"));

    // 1. Build Merkle Tree
    const tree = buildMerkleTree(leafHashes);
    assert.ok(tree.root.length === 64, "Root must be 64-char SHA-256 hex");
    assert.equal(tree.leaves.length, 5);

    // 2. Generate and verify proof for leaf 2
    const targetIdx = 2;
    const targetLeaf = leafHashes[targetIdx];
    const proof = generateMerkleProof(leafHashes, targetIdx);
    assert.ok(proof.length > 0, "Proof should contain branch elements");

    const isValid = verifyMerkleProof(targetLeaf, proof, tree.root);
    assert.equal(isValid, true, "Merkle inclusion proof must be mathematically valid");

    // 3. Tampered leaf must fail verification
    const tamperedLeaf = crypto.createHash("sha256").update("tampered-data").digest("hex");
    const isTamperedValid = verifyMerkleProof(tamperedLeaf, proof, tree.root);
    assert.equal(isTamperedValid, false, "Tampered leaf must fail Merkle proof verification");
  });

  await t.test("Hash-Chain Integrity: Validates unbroken chain and pinpoints tampering", () => {
    // 1. Construct a verifiable 3-element hash chain
    const genesisHash = crypto.createHash("sha256").update("GENESIS_INIT").digest("hex");
    const genesis: HashChainAuditRecord = {
      id: "ev-0",
      tenant_id: "acme-tenant",
      event_type: "GENESIS",
      actor_id: "system",
      payload: { init: true },
      prev_hash: "0".repeat(64),
      current_hash: genesisHash,
      created_at: new Date().toISOString(),
    };

    const ev1Payload = { action: "ISOLATE", host: "SRV-01" };
    const ev1Hash = computeEventHash(genesis.current_hash, "usr-secops", ev1Payload);
    const ev1: HashChainAuditRecord = {
      id: "ev-1",
      tenant_id: "acme-tenant",
      event_type: "HOST_ISOLATED",
      actor_id: "usr-secops",
      payload: ev1Payload,
      prev_hash: genesis.current_hash,
      current_hash: ev1Hash,
      created_at: new Date().toISOString(),
    };

    const ev2Payload = { action: "VERIFY", result: "VERIFIED" };
    const ev2Hash = computeEventHash(ev1.current_hash, "usr-secops", ev2Payload);
    const ev2: HashChainAuditRecord = {
      id: "ev-2",
      tenant_id: "acme-tenant",
      event_type: "VERIFICATION_SUCCESS",
      actor_id: "usr-secops",
      payload: ev2Payload,
      prev_hash: ev1.current_hash,
      current_hash: ev2Hash,
      created_at: new Date().toISOString(),
    };

    const validChain = [genesis, ev1, ev2];

    // 2. Verify valid chain
    const validResult = verifyHashChainIntegrity(validChain);
    assert.equal(validResult.valid, true);
    assert.equal(validResult.chainLength, 3);
    assert.equal(validResult.headHash, ev2Hash);

    // 3. Detect payload tampering in ev1
    const tamperedPayloadChain: HashChainAuditRecord[] = [
      genesis,
      {
        ...ev1,
        payload: { action: "ISOLATE", host: "SRV-01-ATTACKER-MODIFIED" }, // Modified without re-hashing
      },
      ev2,
    ];

    const tamperResult = verifyHashChainIntegrity(tamperedPayloadChain);
    assert.equal(tamperResult.valid, false);
    assert.equal(tamperResult.brokenIndex, 1);
    assert.match(tamperResult.reason || "", /TAMPER_DETECTED/);

    // 4. Detect sequence break (swapped order or severed link)
    const brokenSequenceChain: HashChainAuditRecord[] = [
      genesis,
      {
        ...ev1,
        prev_hash: "severed_hash_value_1234567890",
      },
      ev2,
    ];

    const brokenResult = verifyHashChainIntegrity(brokenSequenceChain);
    assert.equal(brokenResult.valid, false);
    assert.match(brokenResult.reason || "", /CHAIN_BROKEN|TAMPER_DETECTED/);
  });

  await t.test("Cryptographic Evidence Package Generation: Self-contained auditor bundle", () => {
    const pkg = generateEvidencePackage(auditorUser);

    assert.ok(pkg.manifest.packageId.startsWith("EVID-ACME-TENANT-"));
    assert.equal(pkg.manifest.tenantId, "acme-tenant");
    assert.equal(pkg.manifest.algorithm, "HMAC-SHA256");
    assert.ok(pkg.manifest.signature.length === 64, "Signature must be 64-char hex string");
    assert.ok(pkg.manifest.merkleRoot.length === 64, "Merkle root must be 64-char hex string");

    assert.ok(pkg.events.length > 0, "Package must contain tenant events");
    assert.ok(pkg.complianceControls.length >= 9, "Package must contain ISO 27001 / SOC 2 control mappings");
    assert.ok(pkg.offlineVerificationScript.includes("Standalone Cryptographic Evidence Verifier"), "Must embed auditor script");

    // Verify all events have corresponding Merkle proof
    for (let i = 0; i < pkg.events.length; i++) {
      assert.ok(pkg.merkleProofs[i], `Event ${i} must have Merkle proof`);
    }
  });
});
