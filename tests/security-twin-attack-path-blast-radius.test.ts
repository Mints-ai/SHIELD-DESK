import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { SecurityDigitalTwin } from "../src/lib/security-twin/digitalTwin";
import { AttackPathEngine } from "../src/lib/attack-path/engine";
import { BlastRadiusEngine } from "../src/lib/blast-radius/engine";

test("Phase 14, 15, 16: Security Digital Twin, Attack Path, and Blast Radius Suite", async (t) => {
  const tenantId = "tenant-enterprise-sec";

  t.beforeEach(() => {
    SecurityDigitalTwin.clear(tenantId);
  });

  await t.test("SecurityDigitalTwin: Correctly maps assets and evaluates graph queries", () => {
    // Populate twin topology
    SecurityDigitalTwin.upsertNode({
      id: "ep-api-gw",
      tenantId,
      name: "Public API Gateway",
      type: "api",
      criticality: "high",
      environment: "dmz",
      tags: ["internet-facing", "public"],
    });

    SecurityDigitalTwin.upsertNode({
      id: "srv-app-01",
      tenantId,
      name: "Order Processing Service",
      type: "server",
      criticality: "high",
      environment: "internal",
    });

    SecurityDigitalTwin.upsertNode({
      id: "db-customer-01",
      tenantId,
      name: "Customer Records Database",
      type: "database",
      criticality: "critical",
      environment: "internal",
      metadata: { storesPii: true },
    });

    SecurityDigitalTwin.upsertNode({
      id: "svc-checkout",
      tenantId,
      name: "Checkout Business Service",
      type: "business_service",
      criticality: "critical",
    });

    SecurityDigitalTwin.upsertNode({
      id: "vuln-log4j",
      tenantId,
      name: "CVE-2021-44228",
      type: "vulnerability",
      criticality: "critical",
    });

    // Edges
    SecurityDigitalTwin.upsertEdge({
      id: "edge-1",
      tenantId,
      sourceId: "ep-api-gw",
      targetId: "srv-app-01",
      relationType: "can_reach",
      port: 8080,
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-2",
      tenantId,
      sourceId: "srv-app-01",
      targetId: "db-customer-01",
      relationType: "connects_to",
      port: 5432,
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-3",
      tenantId,
      sourceId: "svc-checkout",
      targetId: "db-customer-01",
      relationType: "depends_on",
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-4",
      tenantId,
      sourceId: "srv-app-01",
      targetId: "vuln-log4j",
      relationType: "has_vulnerability",
    });

    // 1. Dependencies Query: What depends on db-customer-01?
    const deps = SecurityDigitalTwin.getDependencies(tenantId, "db-customer-01");
    assert.equal(deps.length, 2);
    const depNames = deps.map((d) => d.name);
    assert.ok(depNames.includes("Checkout Business Service"));
    assert.ok(depNames.includes("Order Processing Service"));

    // 2. Reachability Query: What can reach srv-app-01?
    const reach = SecurityDigitalTwin.getInboundReachability(tenantId, "srv-app-01");
    assert.equal(reach.length, 1);
    assert.equal(reach[0].name, "Public API Gateway");

    // 3. Vulnerabilities: What vulnerabilities exist on srv-app-01?
    const vulns = SecurityDigitalTwin.getVulnerabilities(tenantId, "srv-app-01");
    assert.equal(vulns.length, 1);
    assert.equal(vulns[0].name, "CVE-2021-44228");

    // 4. Business Services Impact
    const impactedServices = SecurityDigitalTwin.getImpactedBusinessServices(tenantId, "db-customer-01");
    assert.equal(impactedServices.length, 1);
    assert.equal(impactedServices[0].name, "Checkout Business Service");

    // 5. Isolation Simulation
    const sim = SecurityDigitalTwin.simulateIsolation(tenantId, "srv-app-01");
    assert.equal(sim.isolatedAssetId, "srv-app-01");
    assert.ok(sim.severedEdgesCount >= 2);
    assert.ok(sim.blastRadiusScore > 20);
  });

  await t.test("AttackPathEngine: Computes deterministic kill-chain and critical choke points", () => {
    // Setup identical network topology
    SecurityDigitalTwin.upsertNode({
      id: "ep-api-gw",
      tenantId,
      name: "Public API Gateway",
      type: "api",
      criticality: "medium",
      environment: "dmz",
      tags: ["internet-facing"],
    });

    SecurityDigitalTwin.upsertNode({
      id: "srv-app-01",
      tenantId,
      name: "Internal App Server",
      type: "server",
      criticality: "high",
      environment: "internal",
    });

    SecurityDigitalTwin.upsertNode({
      id: "db-customer-01",
      tenantId,
      name: "Crown Jewel DB",
      type: "database",
      criticality: "critical",
      environment: "internal",
    });

    SecurityDigitalTwin.upsertNode({
      id: "bs-billing",
      tenantId,
      name: "Billing System",
      type: "business_service",
      criticality: "critical",
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-1",
      tenantId,
      sourceId: "ep-api-gw",
      targetId: "srv-app-01",
      relationType: "can_reach",
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-2",
      tenantId,
      sourceId: "srv-app-01",
      targetId: "db-customer-01",
      relationType: "connects_to",
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-3",
      tenantId,
      sourceId: "bs-billing",
      targetId: "db-customer-01",
      relationType: "depends_on",
    });

    const report = AttackPathEngine.analyzeAttackPaths(tenantId, "db-customer-01");

    assert.ok(report.pathsFoundCount >= 1);
    const path = report.paths[0];
    assert.equal(path.targetAssetId, "db-customer-01");
    assert.equal(path.entryPointAssetId, "ep-api-gw");

    // Must verify Rule: Every attack-path claim must reference evidence
    assert.ok(path.evidence.length >= 2);
    for (const step of path.steps) {
      assert.ok(step.evidence.length > 0, `Step ${step.stepIndex} must cite concrete evidence`);
    }

    // Must identify srv-app-01 as the critical choke point
    assert.ok(report.criticalChokePoints.length > 0);
    assert.equal(report.criticalChokePoints[0].assetId, "srv-app-01");
    assert.ok(report.criticalChokePoints[0].pathsSevered >= 1);
  });

  await t.test("BlastRadiusEngine: Distinguishes measured vs estimated calculation modes", () => {
    // Unmapped asset -> estimated mode
    const unmappedReport = BlastRadiusEngine.calculateBlastRadius(
      tenantId,
      "unmapped-asset-99",
      "isolate_host"
    );
    assert.equal(unmappedReport.calculationMode, "estimated");
    assert.ok(unmappedReport.confidence < 0.5);

    // Mapped asset in Digital Twin -> measured mode
    SecurityDigitalTwin.upsertNode({
      id: "mapped-srv-01",
      tenantId,
      name: "Production Worker",
      type: "server",
      criticality: "critical",
      environment: "production",
    });

    SecurityDigitalTwin.upsertNode({
      id: "bs-crm",
      tenantId,
      name: "CRM Business Service",
      type: "business_service",
      criticality: "critical",
    });

    SecurityDigitalTwin.upsertEdge({
      id: "mapped-edge-1",
      tenantId,
      sourceId: "bs-crm",
      targetId: "mapped-srv-01",
      relationType: "depends_on",
    });

    const mappedReport = BlastRadiusEngine.calculateBlastRadius(
      tenantId,
      "mapped-srv-01",
      "isolate_host"
    );

    assert.equal(mappedReport.calculationMode, "measured");
    assert.ok(mappedReport.confidence >= 0.9);
    assert.ok(mappedReport.score > 50);
    assert.equal(mappedReport.exceeded, true); // Critical business service disrupted mandates escalation
    assert.equal(mappedReport.businessImpact.revenueImpactTier, "critical");
    assert.ok(mappedReport.evidence.length >= 3);
  });
});
