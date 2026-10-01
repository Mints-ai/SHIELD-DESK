import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { getTrivyBinaryPath, isTrivyAvailable, runTrivyScan } from "../src/lib/trivy";

describe("Trivy Vulnerability Scanner Suite", () => {
  test("Binary Discovery: Finds local or system Trivy executable", () => {
    const binPath = getTrivyBinaryPath();
    assert.ok(binPath, "getTrivyBinaryPath should resolve an existing binary");
    assert.strictEqual(isTrivyAvailable(), true, "isTrivyAvailable should return true when binary exists");
  });

  test("Security: Blocks command line flag and argument injection in target", async () => {
    await assert.rejects(
      async () => {
        await runTrivyScan("--debug");
      },
      {
        message: /cannot start with a hyphen or CLI flag/i,
      }
    );

    await assert.rejects(
      async () => {
        await runTrivyScan("-v");
      },
      {
        message: /cannot start with a hyphen or CLI flag/i,
      }
    );
  });

  test("Security: Blocks nonexistent filesystem paths safely", async () => {
    await assert.rejects(
      async () => {
        await runTrivyScan("some/completely/nonexistent/directory/path/12345");
      },
      {
        message: /Target path does not exist on filesystem/i,
      }
    );
  });

  test("Execution: Scans workspace package files and outputs structured findings", async () => {
    const result = await runTrivyScan(".", "fs");

    assert.ok(result, "Result object should be returned");
    assert.ok(Array.isArray(result.findings), "Findings should be an array");
    assert.ok(result.summary, "Summary metrics object should be present");
    assert.ok(typeof result.summary.critical === "number", "Summary should track critical count");
    assert.ok(typeof result.summary.high === "number", "Summary should track high count");
    assert.ok(typeof result.summary.medium === "number", "Summary should track medium count");
    assert.ok(typeof result.summary.low === "number", "Summary should track low count");
    assert.ok(result.scanDurationMs >= 0, "Scan duration should be positive number");

    if (result.findings.length > 0) {
      const first = result.findings[0];
      assert.ok(first.cve_id, "Finding must have cve_id");
      assert.ok(first.package_name, "Finding must have package_name");
      assert.ok(first.severity, "Finding must have severity");
      assert.ok(first.installed_version, "Finding must have installed_version");
      assert.ok(first.remediation, "Finding must include actionable remediation");
    }
  });

  test("Compatibility: Normalizes container /app path gracefully on non-container hosts", async () => {
    const result = await runTrivyScan("/app", "fs");
    assert.ok(result, "Scanning /app should safely resolve without throwing");
    assert.ok(Array.isArray(result.findings), "Findings array should be returned");
  });
});
