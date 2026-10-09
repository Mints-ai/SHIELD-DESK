import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { POST } from "../src/app/api/ingest/webhooks/route";
import { NextRequest } from "next/server";

test("ShieldDesk Public Ingestion & Webhook Normalizer Suite", async (t) => {
  await t.test("Ingests CrowdStrike Falcon alerts with high severity normalization", async () => {
    const req = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-api-key": "test-ingest-api-key-12345",
        "x-shielddesk-tenant": "acme-tenant",
      },
      body: JSON.stringify({
        event: {
          DetectName: "Credential Dumping via LSASS Memory Injection",
          DetectDescription: "Adversary attempted to extract plaintext credentials using procdump",
          ComputerName: "FIN-WS-099",
          Severity: 4,
          CommandLine: "procdump.exe -ma lsass.exe",
        },
      }),
    });

    const res = await POST(req);
    assert.equal(res.status, 200);

    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.source, "CrowdStrike Falcon");
    assert.equal(body.tenantId, "acme-tenant");
    assert.equal(body.severity, "critical");
    assert.equal(body.hostname, "FIN-WS-099");
    assert.match(body.incidentCode, /^INC-\d+$/);
  });

  await t.test("Ingests Microsoft Defender alerts and extracts embedded CVE IDs", async () => {
    const req = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-api-key": "test-ingest-api-key-12345",
        "x-shielddesk-tenant": "acme-tenant",
      },
      body: JSON.stringify({
        title: "Remote Code Execution in Print Spooler",
        severity: "High",
        machineDnsName: "DC-SRV-001.acme.corp",
        description: "Exploitation of PrintNightmare vulnerability documented in CVE-2021-34527 detected on domain controller.",
      }),
    });

    const res = await POST(req);
    assert.equal(res.status, 200);

    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.source, "Microsoft Defender");
    assert.equal(body.severity, "high");
    assert.equal(body.hostname, "DC-SRV-001.acme.corp");
    assert.ok(body.linkedCves.includes("CVE-2021-34527"));
  });

  await t.test("Ingests Wazuh alert and maps rule level to operational severity", async () => {
    const req = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-api-key": "test-globex-ingest-key",
        "x-shielddesk-tenant": "globex-tenant",
      },
      body: JSON.stringify({
        rule: {
          id: "100201",
          level: 13,
          description: "Multiple failed SSH authentication attempts from external IP",
        },
        agent: {
          id: "001",
          name: "GLX-EDGE-ROUTER",
        },
      }),
    });

    const res = await POST(req);
    assert.equal(res.status, 200);

    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.source, "Wazuh HIDS");
    assert.equal(body.tenantId, "globex-tenant");
    assert.equal(body.severity, "critical");
    assert.equal(body.hostname, "GLX-EDGE-ROUTER");
  });

  await t.test("Ingests SIEM alert with HMAC signature and links asset and CVEs", async () => {
    const payload = JSON.stringify({
      source: "defender",
      title: "Suspicious PowerShell Execution with Shadow Copy Tampering",
      severity: "high",
      hostname: "anandbarjun",
      description: "Suspicious encoded command attempting vssadmin delete shadows /all referencing CVE-2020-6240",
    });

    const secret = process.env.SHIELDDESK_WEBHOOK_SECRET || "sd_webhook_dev_secret";
    const signature = "sha256=" + (await import("node:crypto")).default.createHmac("sha256", secret).update(payload).digest("hex");

    const { POST: postSiem } = await import("../src/app/api/ingest/siem/route");
    const req = new NextRequest("http://localhost:3000/api/ingest/siem", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-signature": signature,
        "x-shielddesk-tenant-id": "acme-tenant",
      },
      body: payload,
    });

    const res = await postSiem(req);
    assert.equal(res.status, 201);

    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.source, "defender");
    assert.equal(body.hostname, "anandbarjun");
    assert.equal(body.severity, "high");
    assert.ok(body.linkedCves.includes("CVE-2020-6240"));
  });

  await t.test("Rejects malformed JSON body with 400 Bad Request", async () => {
    const req = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-api-key": "test-ingest-api-key-12345",
      },
      body: "INVALID_JSON_PAYLOAD",
    });

    const res = await POST(req);
    assert.equal(res.status, 400);
  });
});
