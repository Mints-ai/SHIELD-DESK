import "./setup";
import { test } from "node:test";
import assert from "node:assert/strict";
import { getLastScanResult, setLastScanResult, type ScanResult } from "../src/lib/trivy";
import { getLastGitleaksScanResult, setLastGitleaksScanResult, type GitleaksScanResult } from "../src/lib/gitleaks";

test("Trivy cache misses and clearing one tenant cannot reveal another tenant's scan", () => {
  const scan: ScanResult = { findings: [], summary: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 }, scannedTarget: "tenant-a-private", scanDurationMs: 1, binaryPath: "test" };
  setLastScanResult(scan, "trivy-cache-a");
  assert.equal(getLastScanResult("trivy-cache-a"), scan);
  assert.equal(getLastScanResult("trivy-cache-b"), null);
  setLastScanResult(null, "trivy-cache-b");
  assert.equal(getLastScanResult("trivy-cache-b"), null);
  assert.equal(getLastScanResult("trivy-cache-a"), scan);
  setLastScanResult(null, "trivy-cache-a");
  assert.equal(getLastScanResult("trivy-cache-a"), null);
  assert.throws(() => setLastScanResult(scan, ""), /Tenant ID is required/);
});

test("Gitleaks cache misses and clearing one tenant cannot reveal another tenant's scan", () => {
  const scan: GitleaksScanResult = { findings: [], summary: { critical: 1, high: 0, medium: 0, total: 1 }, scannedTarget: "tenant-a-private", scanDurationMs: 1, binaryPath: "test", scanMode: "filesystem", redacted: true };
  setLastGitleaksScanResult(scan, "gitleaks-cache-a");
  assert.equal(getLastGitleaksScanResult("gitleaks-cache-a"), scan);
  assert.equal(getLastGitleaksScanResult("gitleaks-cache-b"), null);
  setLastGitleaksScanResult(null, "gitleaks-cache-b");
  assert.equal(getLastGitleaksScanResult("gitleaks-cache-b"), null);
  assert.equal(getLastGitleaksScanResult("gitleaks-cache-a"), scan);
  setLastGitleaksScanResult(null, "gitleaks-cache-a");
  assert.equal(getLastGitleaksScanResult("gitleaks-cache-a"), null);
  assert.throws(() => setLastGitleaksScanResult(scan, ""), /Tenant ID is required/);
});
