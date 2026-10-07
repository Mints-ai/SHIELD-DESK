import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as yaraRulesGET, POST as yaraRulesPOST } from "@/app/api/threats/yara/route";
import { PATCH as yaraRulePATCH, DELETE as yaraRuleDELETE } from "@/app/api/threats/yara/[id]/route";
import { POST as yaraTestPOST } from "@/app/api/threats/yara/test/route";
import { GET as yaraMatchesGET } from "@/app/api/threats/yara/matches/route";
import { POST as telemetryPOST } from "@/app/api/agent/telemetry/route";
import { createSessionToken } from "@/lib/auth/token";
import { evaluateTelemetryBatch } from "@/lib/detection/engine";
import { resetYaraMemoryStore } from "@/lib/detection/yara/store";

test("SD-027: YARA Rule Management REST API & End-to-End Telemetry Suite", async (t) => {
  resetYaraMemoryStore();

  const adminToken = createSessionToken({
    uid: "usr-admin-01",
    email: "admin@acme.corp",
    tenantId: "acme-tenant",
    role: "system_admin",
  });

  await t.test("GET /api/threats/yara: Returns default system rules with match statistics", async () => {
    const req = new NextRequest("http://localhost:3000/api/threats/yara?tenant_id=acme-tenant", {
      headers: {
        authorization: `Bearer ${adminToken}`,
      },
    });

    const res = await yaraRulesGET(req);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.ok(Array.isArray(data.rules));
    assert.ok(data.rules.length >= 5);

    const r1 = data.rules.find((r: any) => r.rule_id === "YARA-MAL-001");
    assert.ok(r1);
    assert.strictEqual(r1.name, "WebShell_C99_PHP");
    assert.strictEqual(r1.is_system, true);

    const r2 = data.rules.find((r: any) => r.rule_id === "YARA-MAL-002");
    assert.ok(r2);
    assert.strictEqual(r2.name, "Ransomware_LockBit_Indicators");
  });

  await t.test("POST /api/threats/yara: Rejects invalid YARA syntax with 400 and error location", async () => {
    const badPayload = {
      raw_content: `
        rule Bad_Rule {
          meta:
            id = "INVALID"
          strings
            $s1 = "foo"
          condition:
            $s1
        }
      `,
    };

    const req = new NextRequest("http://localhost:3000/api/threats/yara", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(badPayload),
    });

    const res = await yaraRulesPOST(req);
    assert.strictEqual(res.status, 400);
    const data = await res.json();
    assert.strictEqual(data.error, "Syntax error in YARA rule");
    assert.ok(typeof data.line === "number");
    assert.ok(typeof data.column === "number");
  });

  let createdCustomRuleId = "";

  await t.test("POST /api/threats/yara: Creates valid custom rule successfully", async () => {
    const goodRule = {
      name: "Custom_PowerShell_Beacon",
      category: "C2 / Post-Exploitation",
      severity: "high",
      target: "process memory",
      description: "Detects custom Cobalt Strike beacon stager in PowerShell",
      raw_content: `
        rule Custom_PowerShell_Beacon {
          meta:
            id = "YARA-CUST-999"
            description = "Custom Cobalt Strike Beacon"
            severity = "high"
          strings:
            $p1 = "Invoke-ReflectivePEInjection" nocase
            $p2 = "BeaconPayload" ascii
          condition:
            any of them
        }
      `,
    };

    const req = new NextRequest("http://localhost:3000/api/threats/yara", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(goodRule),
    });

    const res = await yaraRulesPOST(req);
    assert.strictEqual(res.status, 201);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.ok(data.rule);
    assert.strictEqual(data.rule.name, "Custom_PowerShell_Beacon");
    assert.strictEqual(data.rule.is_system, false);
    createdCustomRuleId = data.rule.id;
  });

  await t.test("PATCH /api/threats/yara/[id]: Toggles rule active/disabled state", async () => {
    assert.ok(createdCustomRuleId);
    const req = new NextRequest(`http://localhost:3000/api/threats/yara/${createdCustomRuleId}`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ enabled: false }),
    });

    const res = await yaraRulePATCH(req, { params: Promise.resolve({ id: createdCustomRuleId }) });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.rule.enabled, false);
  });

  await t.test("DELETE /api/threats/yara/[id]: Protects system rules from deletion (403 Forbidden)", async () => {
    const req = new NextRequest("http://localhost:3000/api/threats/yara/YARA-MAL-001", {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${adminToken}`,
      },
    });

    const res = await yaraRuleDELETE(req, { params: Promise.resolve({ id: "YARA-MAL-001" }) });
    assert.strictEqual(res.status, 403);
    const data = await res.json();
    assert.strictEqual(data.error, "System default rules cannot be deleted");
  });

  await t.test("DELETE /api/threats/yara/[id]: Deletes custom rule successfully", async () => {
    assert.ok(createdCustomRuleId);
    const req = new NextRequest(`http://localhost:3000/api/threats/yara/${createdCustomRuleId}`, {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${adminToken}`,
      },
    });

    const res = await yaraRuleDELETE(req, { params: Promise.resolve({ id: createdCustomRuleId }) });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.deletedId, createdCustomRuleId);
  });

  await t.test("POST /api/threats/yara/test: Dry-run test sandbox evaluates candidate payloads", async () => {
    const req = new NextRequest("http://localhost:3000/api/threats/yara/test", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        rule_id: "YARA-MAL-001",
        sample_payload: "<?php c99shell(); passthru($_POST['cmd']); ?>",
      }),
    });

    const res = await yaraTestPOST(req);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.matched, true);
    assert.strictEqual(data.ruleName, "WebShell_C99_PHP");
    assert.ok(data.matchesCount >= 1);
    assert.ok(typeof data.executionTimeMs === "number");
  });

  await t.test("GET /api/threats/yara/matches: Returns recorded detection match logs", async () => {
    const req = new NextRequest("http://localhost:3000/api/threats/yara/matches?tenant_id=acme-tenant", {
      headers: {
        authorization: `Bearer ${adminToken}`,
      },
    });

    const res = await yaraMatchesGET(req);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.success, true);
    assert.ok(Array.isArray(data.matches));
  });

  await t.test("End-to-End Telemetry Scanning: Matching webshell triggers incident & match record", async () => {
    const testEvents = [
      {
        eventType: "file_creation",
        payload: {
          file_path: "/var/www/wordpress/wp-content/uploads/backdoor.php",
          content: "<?php // C99 backdoor snippet\n c99shell();\n passthru($_POST['cmd']); ?>",
        },
      },
    ];

    const detections = await evaluateTelemetryBatch(testEvents, {
      agentId: "ws-fin-01",
      tenantId: "acme-tenant",
      hostname: "FIN-SRV-WEB01",
    });

    assert.ok(detections.length >= 1);
    const yaraDetection = detections.find((d) => d.ruleId === "YARA-MAL-001");
    assert.ok(yaraDetection);
    assert.strictEqual(yaraDetection.ruleName, "WebShell_C99_PHP");
    assert.strictEqual(yaraDetection.severity, "critical");
    assert.ok(yaraDetection.incidentId);
    assert.ok(yaraDetection.incidentCode?.startsWith("INC-"));

    // Verify match was recorded in matches endpoint
    const matchesReq = new NextRequest("http://localhost:3000/api/threats/yara/matches?tenant_id=acme-tenant", {
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const matchesRes = await yaraMatchesGET(matchesReq);
    const matchesData = await matchesRes.json();
    const recorded = matchesData.matches.find((m: any) => m.rule_id === "YARA-MAL-001");
    assert.ok(recorded);
    assert.strictEqual(recorded.agent_id, "ws-fin-01");
  });
});
