/**
 * Phase F: Evidence Vault Test Suite
 *
 * Verifies:
 * 1. AuditExportGenerator creates verifiable CryptographicEvidencePackage (JSON)
 * 2. AuditExportGenerator creates RFC-4180 CSV with cryptographic attestations
 * 3. Cryptographic integrity headers (X-ShieldDesk-*) in export bundles
 * 4. Merkle proof mathematical verification for every audit event
 * 5. Tamper detection: Pinpoints payload tampering, Merkle root mismatch, and signature invalidation
 * 6. Standalone verification python script included in bundle
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { AuditExportGenerator } from "../src/lib/compliance/exportGenerator";
import { HashChainAuditRecord } from "../src/lib/fleet/fleet";

test("Phase F: Evidence Vault & Export Generator Suite", async (t) => {
  const tenantId = "tenant-audit-vault";
  const exportedBy = "usr-lead-auditor";

  // Build a sample valid 4-event hash chain
  const genesisHash = crypto.createHash("sha256").update("GENESIS_BLOCK").digest("hex");
  const event1Payload = { commandId: "cmd-001", action: "isolate_host", status: "VERIFIED" };
  const event1Hash = crypto
    .createHash("sha256")
    .update(`${genesisHash}|agent:001|${JSON.stringify(event1Payload)}`)
    .digest("hex");

  const event2Payload = { commandId: "cmd-002", action: "package_upgrade", status: "VERIFIED" };
  const event2Hash = crypto
    .createHash("sha256")
    .update(`${event1Hash}|agent:002|${JSON.stringify(event2Payload)}`)
    .digest("hex");

  const event3Payload = { commandId: "cmd-003", action: "apply_config", status: "VERIFIED" };
  const event3Hash = crypto
    .createHash("sha256")
    .update(`${event2Hash}|agent:003|${JSON.stringify(event3Payload)}`)
    .digest("hex");

  const sampleEvents: HashChainAuditRecord[] = [
    {
      id: "ev-0",
      tenant_id: tenantId,
      event_type: "GENESIS",
      actor_id: "system",
      payload: {},
      prev_hash: "0".repeat(64),
      current_hash: genesisHash,
      created_at: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: "ev-1",
      tenant_id: tenantId,
      event_type: "REMEDIATION_VERIFIED_SUCCESS",
      actor_id: "agent:001",
      payload: event1Payload,
      prev_hash: genesisHash,
      current_hash: event1Hash,
      created_at: new Date(Date.now() - 2400000).toISOString(),
    },
    {
      id: "ev-2",
      tenant_id: tenantId,
      event_type: "REMEDIATION_VERIFIED_SUCCESS",
      actor_id: "agent:002",
      payload: event2Payload,
      prev_hash: event1Hash,
      current_hash: event2Hash,
      created_at: new Date(Date.now() - 1200000).toISOString(),
    },
    {
      id: "ev-3",
      tenant_id: tenantId,
      event_type: "REMEDIATION_VERIFIED_SUCCESS",
      actor_id: "agent:003",
      payload: event3Payload,
      prev_hash: event2Hash,
      current_hash: event3Hash,
      created_at: new Date().toISOString(),
    },
  ];

  // =========================================================================
  // 1. JSON Cryptographic Evidence Package
  // =========================================================================
  await t.test("AuditExportGenerator: Generates tamper-evident JSON bundle with Merkle root and proofs", async () => {
    const bundle = await AuditExportGenerator.generateBundle({
      tenantId,
      exportedBy,
      format: "json",
      customEvents: sampleEvents,
      persistRecord: false,
    });

    assert.equal(bundle.format, "json");
    assert.equal(bundle.totalEvents, 4);
    assert.ok(bundle.packageId.startsWith(`EVID-${tenantId.toUpperCase()}`));
    assert.equal(bundle.contentType, "application/json; charset=utf-8");

    // Check HTTP headers
    assert.equal(bundle.headers["X-ShieldDesk-Package-Id"], bundle.packageId);
    assert.equal(bundle.headers["X-ShieldDesk-Tenant-Id"], tenantId);
    assert.ok(bundle.headers["X-ShieldDesk-Merkle-Root"].length === 64);
    assert.equal(bundle.headers["X-ShieldDesk-Chain-Head"], event3Hash);
    assert.ok(bundle.headers["X-ShieldDesk-Signature"].length === 64);
    assert.equal(bundle.headers["X-ShieldDesk-Event-Count"], "4");

    // Parse payload and verify internal structure
    const parsed = JSON.parse(bundle.data);
    assert.equal(parsed.manifest.packageId, bundle.packageId);
    assert.equal(parsed.events.length, 4);
    assert.ok(parsed.merkleProofs[0]);
    assert.ok(parsed.merkleProofs[3]);
    assert.ok(parsed.offlineVerificationScript.includes("verify_evidence"));

    // Verify package validity
    const verification = AuditExportGenerator.verifyPackage(parsed);
    assert.equal(verification.valid, true);
  });

  // =========================================================================
  // 2. CSV Evidence Package with Cryptographic Attestations
  // =========================================================================
  await t.test("AuditExportGenerator: Generates RFC-4180 compliant CSV with header metadata", async () => {
    const bundle = await AuditExportGenerator.generateBundle({
      tenantId,
      exportedBy,
      format: "csv",
      customEvents: sampleEvents,
      persistRecord: false,
    });

    assert.equal(bundle.format, "csv");
    assert.equal(bundle.contentType, "text/csv; charset=utf-8");
    assert.ok(bundle.headers["Content-Disposition"].includes(`${bundle.packageId}.csv`));

    // Verify CSV contents
    const lines = bundle.data.split("\r\n");
    assert.ok(lines[0].startsWith("# ShieldDesk Cryptographic Audit Ledger Export"));
    assert.ok(lines[1].includes(bundle.packageId));
    assert.ok(lines[7].includes(bundle.headers["X-ShieldDesk-Merkle-Root"]));

    // Check CSV column headers
    const headerLine = lines.find((l) => l.startsWith('"sequence_number"'));
    assert.ok(headerLine);
    assert.ok(headerLine.includes("current_hash"));
    assert.ok(headerLine.includes("merkle_leaf_hash"));

    // Check data row count (header comment lines + header + 4 data rows)
    const dataRows = lines.filter((l) => /^\s*"\d+"/.test(l));
    assert.equal(dataRows.length, 4);
    assert.ok(dataRows[0].includes("GENESIS"));
    assert.ok(dataRows[1].includes("isolate_host"));
  });

  // =========================================================================
  // 3. Cryptographic Tamper Detection
  // =========================================================================
  await t.test("AuditExportGenerator: Mathematically catches payload tampering, broken links, and altered metadata", async () => {
    const originalPackage = AuditExportGenerator.buildPackage(tenantId, exportedBy, sampleEvents);
    assert.equal(AuditExportGenerator.verifyPackage(originalPackage).valid, true);

    // Tamper 1: Modify event payload content
    const tamperedPayloadPkg = JSON.parse(JSON.stringify(originalPackage));
    tamperedPayloadPkg.events[1].payload.action = "unauthorized_override";
    const t1Res = AuditExportGenerator.verifyPackage(tamperedPayloadPkg);
    assert.equal(t1Res.valid, false);
    assert.ok(t1Res.reason?.includes("TAMPER_DETECTED"));

    // Tamper 2: Modify event current_hash to try to bypass payload check
    const tamperedHashPkg = JSON.parse(JSON.stringify(originalPackage));
    tamperedHashPkg.events[2].current_hash = "a".repeat(64);
    const t2Res = AuditExportGenerator.verifyPackage(tamperedHashPkg);
    assert.equal(t2Res.valid, false);
    assert.ok(t2Res.reason?.includes("TAMPER_DETECTED") || t2Res.reason?.includes("Merkle Root mismatch"));

    // Tamper 3: Alter manifest event count
    const tamperedCountPkg = JSON.parse(JSON.stringify(originalPackage));
    tamperedCountPkg.manifest.totalEvents = 999;
    const t3Res = AuditExportGenerator.verifyPackage(tamperedCountPkg);
    assert.equal(t3Res.valid, false);
    assert.ok(t3Res.reason?.includes("event count mismatch"));

    // Tamper 4: Alter manifest signature
    const tamperedSigPkg = JSON.parse(JSON.stringify(originalPackage));
    tamperedSigPkg.manifest.signature = "deadbeef".repeat(8);
    const t4Res = AuditExportGenerator.verifyPackage(tamperedSigPkg);
    assert.equal(t4Res.valid, false);
    assert.ok(t4Res.reason?.includes("signature invalid"));
  });
});
