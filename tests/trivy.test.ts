import "./setup";
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { POST as chatPost } from "../src/app/api/chat/route";
import { getTrivyBinaryPath, isTrivyAvailable, runTrivyScan } from "../src/lib/trivy";

describe("Trivy Vulnerability Scanner Suite", () => {
  test("Binary Discovery: Resolves binary status deterministically", () => {
    const binPath = getTrivyBinaryPath();
    const available = isTrivyAvailable();
    if (binPath) {
      assert.ok(typeof binPath === "string", "Binary path should be a valid string");
      assert.strictEqual(available, true, "isTrivyAvailable should return true when binary exists");
    } else {
      assert.strictEqual(binPath, null, "Binary path should be null when missing");
      assert.strictEqual(available, false, "isTrivyAvailable should return false when binary is missing");
    }
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

  test("Execution: Scans workspace package files and outputs structured findings", async (t) => {
    if (!isTrivyAvailable()) {
      await assert.rejects(
        async () => {
          await runTrivyScan(".", "fs");
        },
        {
          message: /Trivy scanner binary not found/i,
        }
      );
      return;
    }

    try {
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
    } catch (err: any) {
      if (err.message?.includes("DB") || err.message?.includes("download") || err.message?.includes("ETIMEDOUT")) {
        t.skip(`Skipping live scan test due to upstream DB reachability: ${err.message}`);
        return;
      }
      throw err;
    }
  });

  test("Compatibility: Normalizes container /app path gracefully on non-container hosts", async (t) => {
    if (!isTrivyAvailable()) {
      await assert.rejects(
        async () => {
          await runTrivyScan("/app", "fs");
        },
        {
          message: /Trivy scanner binary not found/i,
        }
      );
      return;
    }

    try {
      const result = await runTrivyScan("/app", "fs");
      assert.ok(result, "Scanning /app should safely resolve without throwing");
      assert.ok(Array.isArray(result.findings), "Findings array should be returned");
    } catch (err: any) {
      if (err.message?.includes("DB") || err.message?.includes("download") || err.message?.includes("ETIMEDOUT")) {
        t.skip(`Skipping /app normalization live scan due to upstream DB reachability: ${err.message}`);
        return;
      }
      throw err;
    }
  });

  test("Chatbot RBAC: Routes Trivy scan query with role-based formatting and scanner redirection", async (t) => {
    if (!isTrivyAvailable()) {
      t.skip("Skipping chatbot live scan RBAC test: Trivy scanner binary not installed on host.");
      return;
    }

    // 1. Test as Admin
    const reqAdmin = new NextRequest("http://localhost:3000/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({ message: "Run a full Trivy vulnerability scan" }),
    });

    const resAdmin = await chatPost(reqAdmin);
    assert.strictEqual(resAdmin.status, 200);
    const bodyAdmin = await resAdmin.text();
    assert.match(bodyAdmin, /critical\s*-\s*\d+/i);
    assert.match(bodyAdmin, /high\s*-\s*\d+/i);
    assert.match(bodyAdmin, /medium\s*-\s*\d+/i);
    assert.match(bodyAdmin, /low\s*-\s*\d+/i);
    assert.match(bodyAdmin, /Role Authority \(.*Super\s*Admin.*\)/i);
    assert.match(bodyAdmin, /\/dashboard\/scanner\?view=latest/);

    // 2. Test as Analyst
    const reqAnalyst = new NextRequest("http://localhost:3000/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({ message: "Run a full Trivy vulnerability scan" }),
    });

    const resAnalyst = await chatPost(reqAnalyst);
    assert.strictEqual(resAnalyst.status, 200);
    const bodyAnalyst = await resAnalyst.text();
    assert.match(bodyAnalyst, /Role Authority \(Security Operations Analyst\)/i);
    assert.match(bodyAnalyst, /\/dashboard\/scanner\?view=latest/);
  });
});
