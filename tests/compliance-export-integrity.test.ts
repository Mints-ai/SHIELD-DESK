import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { AuditExportGenerator } from "../src/lib/compliance/exportGenerator";
import { verifyHashChainDetailed } from "../src/lib/compliance/verifier";
import { getOrCreateTenantStore } from "../src/lib/compliance/statefulTenantDb";
import type { SessionUser } from "../src/lib/auth/session";

test("SD-028 Compliance Platform: Export Integrity & Cryptographic Verifier", async (t) => {
  const tenantAUser: SessionUser = {
    id: "sec-ops-a",
    tenant_id: "acme-corp",
    role: "system_admin",
  };

  const tenantBUser: SessionUser = {
    id: "sec-ops-b",
    tenant_id: "globex-corp",
    role: "system_admin",
  };

  // Seed both stores
  getOrCreateTenantStore("acme-corp");
  getOrCreateTenantStore("globex-corp");

  await t.test("Tenant Isolation & Genesis Invariant: exactly one Genesis block at index 0", async () => {
    const pkgA = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    const pkgB = await AuditExportGenerator.generatePackage(tenantBUser, "soc-2");

    assert.equal(pkgA.manifest.tenantId, "acme-corp");
    assert.equal(pkgB.manifest.tenantId, "globex-corp");

    // Check Genesis invariant
    assert.ok(pkgA.events.length > 0, "Package A must contain events");
    assert.ok(pkgB.events.length > 0, "Package B must contain events");

    assert.equal(pkgA.events[0].event_type, "GENESIS");
    assert.equal(pkgA.events[0].prev_hash, "0".repeat(64));

    assert.equal(pkgB.events[0].event_type, "GENESIS");
    assert.equal(pkgB.events[0].prev_hash, "0".repeat(64));

    // Ensure no additional GENESIS blocks exist after index 0
    for (let i = 1; i < pkgA.events.length; i++) {
      assert.notEqual(
        pkgA.events[i].event_type,
        "GENESIS",
        `Event at index ${i} must not be a duplicate GENESIS block`
      );
    }
  });

  await t.test("Hash Chain Continuity: every event i links to current_hash of event i-1", async () => {
    const pkg = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    const events = pkg.events;

    for (let i = 1; i < events.length; i++) {
      assert.equal(
        events[i].prev_hash,
        events[i - 1].current_hash,
        `Event #${i} prev_hash must strictly match event #${i - 1} current_hash`
      );
    }
  });

  await t.test("Package Self-Verification: AuditExportGenerator.verifyPackage returns valid=true", async () => {
    const pkg = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    const result = AuditExportGenerator.verifyPackage(pkg);

    assert.equal(result.valid, true, `Verification failed with error: ${result.error}`);
    assert.equal(result.eventsVerified, pkg.events.length);
    assert.equal(result.merkleRootValid, true);
  });

  await t.test("Detailed In-Browser Ledger Verifier: verifyHashChainDetailed recalculates all hashes", async () => {
    const pkg = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    const report = await verifyHashChainDetailed(pkg.events);

    assert.equal(report.valid, true);
    assert.equal(report.brokenLinkCount, 0);
    assert.equal(report.tamperedCount, 0);
    assert.equal(report.blocks.length, pkg.events.length);
    assert.equal(report.headHash, pkg.events[pkg.events.length - 1].current_hash);
    assert.equal(report.merkleRoot, pkg.manifest.merkleRoot);
  });

  await t.test("Tampering Detection: payload mutation is immediately caught", async () => {
    const pkg = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    // Clone package to mutate
    const tamperedPkg = JSON.parse(JSON.stringify(pkg));

    // Tamper with payload of block 1
    if (tamperedPkg.events.length > 1) {
      tamperedPkg.events[1].payload = {
        tampered_key: "attacker_injected_change",
      };

      const result = AuditExportGenerator.verifyPackage(tamperedPkg);
      assert.equal(result.valid, false, "Tampered package must fail verification");
      assert.ok(
        result.error?.includes("TAMPER_DETECTED") ||
        result.error?.includes("Hash mismatch") ||
        result.error?.includes("Merkle root mismatch")
      );

      const detailedReport = await verifyHashChainDetailed(tamperedPkg.events);
      assert.equal(detailedReport.valid, false);
      assert.ok(detailedReport.tamperedCount > 0);
    }
  });

  await t.test("Tampering Detection: block deletion or link severing is caught", async () => {
    const pkg = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    const tamperedPkg = JSON.parse(JSON.stringify(pkg));

    if (tamperedPkg.events.length > 2) {
      // Sever link by changing prev_hash of block 2
      tamperedPkg.events[2].prev_hash = "f".repeat(64);

      const result = AuditExportGenerator.verifyPackage(tamperedPkg);
      assert.equal(result.valid, false, "Severed chain link must fail verification");
      assert.ok(
        result.error?.includes("TAMPER_DETECTED") ||
        result.error?.includes("CHAIN_BROKEN") ||
        result.error?.includes("broken link") ||
        result.error?.includes("does not link")
      );
    }
  });

  await t.test("Tabular CSV Export: generates proper chronological audit trail with hash headers", async () => {
    const csvData = await AuditExportGenerator.generateCsv(tenantAUser);
    assert.ok(
      csvData.includes("event_type") &&
      csvData.includes("current_hash") &&
      csvData.includes("payload_summary")
    );
    assert.ok(csvData.includes("GENESIS"));
    assert.ok(csvData.includes(tenantAUser.tenant_id));
  });

  await t.test("Standalone Python Verifier Script: includes embedded valid syntax", async () => {
    const pkg = await AuditExportGenerator.generatePackage(tenantAUser, "iso-27001");
    assert.ok(
      pkg.verifierScript.includes("def verify_evidence(") ||
      pkg.verifierScript.includes("def verify_bundle(")
    );
    assert.ok(pkg.verifierScript.includes("sort_keys=True"));
    assert.ok(pkg.verifierScript.includes("separators=(',', ':')"));
  });
});
