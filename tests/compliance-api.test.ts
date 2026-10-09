import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as complianceGET } from "../src/app/api/compliance/route";
import { GET as controlDetailGET } from "../src/app/api/compliance/control/[id]/route";
import { GET as verifyGET } from "../src/app/api/compliance/verify/route";
import { POST as scanPOST } from "../src/app/api/compliance/scan/route";
import { GET as reportGET } from "../src/app/api/compliance/report/route";
import { GET as policiesGET, POST as policiesPOST } from "../src/app/api/compliance/policies/route";

test("SD-028 Compliance Platform: API Endpoints & Live Handlers", async (t) => {
  const authHeaders = {
    "X-ShieldDesk-User": "dev-admin",
  };

  await t.test("GET /api/compliance: returns framework summary with live computed score", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance?framework=iso-27001", {
      headers: authHeaders,
    });
    const res = await complianceGET(req);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.frameworkId, "iso27001");
    assert.equal(json.tenantId, "acme-tenant");
    assert.ok(typeof json.overallScore === "number");
    assert.ok(json.controls.length >= 8);
    assert.ok(json.auditEvidenceCount > 0);
  });

  await t.test("GET /api/compliance: switches dynamically to SOC 2 Type II", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance?framework=soc-2", {
      headers: authHeaders,
    });
    const res = await complianceGET(req);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.frameworkId, "soc2");
    assert.ok(json.controls.some((c: { code: string }) => c.code === "CC6.1"));
  });

  await t.test("GET /api/compliance?export=true: exports signed cryptographic JSON evidence package", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance?export=true&format=json&framework=iso-27001", {
      headers: authHeaders,
    });
    const res = await complianceGET(req);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.ok(json.manifest, "Must contain manifest");
    assert.equal(json.manifest.tenantId, "acme-tenant");
    assert.ok(json.manifest.merkleRoot, "Must include Merkle root");
    assert.ok(Array.isArray(json.events), "Must contain chronological events array");
    assert.ok(
      json.verifierScript?.includes("def verify_evidence(") ||
      json.verifierScript?.includes("def verify_bundle(") ||
      json.offlineVerificationScript?.includes("def verify_evidence(")
    );
  });

  await t.test("GET /api/compliance?export=true&format=csv: exports tabular audit trail", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance?export=true&format=csv", {
      headers: authHeaders,
    });
    const res = await complianceGET(req);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("Content-Type"), "text/csv; charset=utf-8");

    const text = await res.text();
    assert.ok(text.includes("event_type"));
    assert.ok(text.includes("current_hash"));
    assert.ok(text.includes("GENESIS"));
  });

  await t.test("GET /api/compliance/control/[id]: retrieves control deep dive and linked evidence", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance/control/A.8.7?framework=iso-27001", {
      headers: authHeaders,
    });
    const res = await controlDetailGET(req, {
      params: Promise.resolve({ id: "A.8.7" }),
    });
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.control.code, "A.8.7");
    assert.ok(json.control.clauseRequirement.length > 0);
    assert.ok(json.control.evidenceRecords.length > 0);
    assert.ok(json.control.linkedPolicies.length >= 0);
  });

  await t.test("GET /api/compliance/verify: recalculates hash-chain integrity in real time", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance/verify", {
      headers: authHeaders,
    });
    const res = await verifyGET(req);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.verification.valid, true);
    assert.equal(json.verification.brokenLinkCount, 0);
    assert.ok(json.verification.blocks.length > 0);
  });

  await t.test("POST /api/compliance/scan: runs live automated compliance audit scan", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance/scan", {
      method: "POST",
      headers: authHeaders,
    });
    const res = await scanPOST(req);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(json.report.checks.length >= 4);
    assert.ok(typeof json.report.passedChecks === "number");
    assert.ok(typeof json.report.healthScore === "number");
  });

  await t.test("GET /api/compliance/report: generates formal auditor package", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance/report?framework=iso-27001", {
      headers: authHeaders,
    });
    const res = await reportGET(req);
    assert.equal(res.status, 200);

    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.report.tenantId, "acme-tenant");
    assert.ok(json.report.digitalSignature.merkleRoot);
    assert.ok(json.report.controlMatrix.length >= 8);
    assert.ok(json.report.attestation.auditorStatement.length > 0);
  });

  await t.test("Policy Vault: lists existing policies and adds a new policy", async () => {
    // 1. GET policies
    const getReq = new NextRequest("http://localhost:3000/api/compliance/policies", {
      headers: authHeaders,
    });
    const getRes = await policiesGET(getReq);
    assert.equal(getRes.status, 200);
    const getJson = await getRes.json();
    assert.ok(Array.isArray(getJson.policies));
    assert.ok(getJson.policies.length >= 3);

    // 2. POST new policy
    const postReq = new NextRequest("http://localhost:3000/api/compliance/policies", {
      method: "POST",
      headers: {
        ...authHeaders,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        policyCode: "POL-SEC-999",
        title: "Quantum Cryptography & Key Management Policy",
        category: "Cryptography",
        description: "Mandatory guidelines for post-quantum key exchange algorithms.",
        version: "2.1",
        controlMappings: ["A.8.24", "PR.DS"],
      }),
    });
    const postRes = await policiesPOST(postReq);
    assert.equal(postRes.status, 201);
    const postJson = await postRes.json();
    assert.equal(postJson.success, true);
    assert.equal(postJson.policy.policyCode, "POL-SEC-999");
    assert.ok(postJson.policy.controlMappings.includes("A.8.24"));
  });
});
