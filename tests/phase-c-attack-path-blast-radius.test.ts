/**
 * Phase C: Attack-Path & Blast-Radius Engines Test Suite
 *
 * Verifies:
 * 1. Reachability and attack-path calculation, ranked by risk score
 * 2. Explainable kill-chain mapping with MITRE ATT&CK techniques
 * 3. Choke-point efficacy calculation and remediation guidance
 * 4. Blast radius analysis across services, apps, users, and sensitive systems
 * 5. Downtime estimation and rollback availability assessment
 * 6. Calculation modes: measured vs. inferred vs. simulated vs. estimated
 * 7. Multi-tenant isolation: Tenant A cannot inspect Tenant B's attack paths
 * 8. Async DB integration with seamless fallback
 * 9. Backward compatibility with existing callers
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { SecurityDigitalTwin } from "../src/lib/security-twin/digitalTwin";
import { AttackPathEngine } from "../src/lib/attack-path/engine";
import { BlastRadiusEngine } from "../src/lib/blast-radius/engine";

test("Phase C: Attack-Path and Blast-Radius Engines Suite", async (t) => {
  const tenantA = "tenant-fintech-prod";
  const tenantB = "tenant-healthcare-corp";

  t.beforeEach(() => {
    SecurityDigitalTwin.clear(tenantA);
    SecurityDigitalTwin.clear(tenantB);
  });

  // Setup rich topology in tenantA
  function seedTenantATopology() {
    // 1. Entry Points
    SecurityDigitalTwin.upsertNode({
      id: "ep-api-gateway",
      tenantId: tenantA,
      name: "Public Customer API Gateway",
      type: "api",
      criticality: "high",
      environment: "dmz",
      ipAddress: "198.51.100.25",
      tags: ["internet-facing", "public"],
    });

    SecurityDigitalTwin.upsertNode({
      id: "ep-vpn-portal",
      tenantId: tenantA,
      name: "Remote Access VPN Portal",
      type: "endpoint",
      criticality: "medium",
      environment: "dmz",
      ipAddress: "198.51.100.30",
      tags: ["internet-facing"],
    });

    // 2. Intermediate Services & Servers (Apps & Microservices)
    SecurityDigitalTwin.upsertNode({
      id: "srv-order-svc",
      tenantId: tenantA,
      name: "Order Processing Service",
      type: "server",
      criticality: "high",
      environment: "internal",
    });

    SecurityDigitalTwin.upsertNode({
      id: "app-payment-gateway",
      tenantId: tenantA,
      name: "Payment Processing Microservice",
      type: "application",
      criticality: "critical",
      environment: "production",
      metadata: { storesPci: true, pci: true },
      tags: ["payment", "pci"],
    });

    SecurityDigitalTwin.upsertNode({
      id: "srv-bastion-host",
      tenantId: tenantA,
      name: "Internal Management Bastion",
      type: "server",
      criticality: "medium",
      environment: "internal",
    });

    // 3. Crown Jewel Database (Target)
    SecurityDigitalTwin.upsertNode({
      id: "db-cust-vault",
      tenantId: tenantA,
      name: "Customer PII & Credit Vault",
      type: "database",
      criticality: "critical",
      environment: "production",
      metadata: { storesPii: true, storesPci: true, sox: true },
      tags: ["crown_jewel", "pii"],
    });

    // 4. Business Services
    SecurityDigitalTwin.upsertNode({
      id: "svc-checkout-core",
      tenantId: tenantA,
      name: "Core E-Commerce Checkout",
      type: "business_service",
      criticality: "critical",
    });

    // 5. User / Identity Node
    SecurityDigitalTwin.upsertNode({
      id: "id-dba-admin",
      tenantId: tenantA,
      name: "Senior Database Administrator",
      type: "identity",
      criticality: "high",
      metadata: { department: "Infrastructure & Security" },
    });

    // 6. Vulnerabilities
    SecurityDigitalTwin.upsertNode({
      id: "vuln-rce-spring",
      tenantId: tenantA,
      name: "CVE-2022-22965",
      type: "vulnerability",
      criticality: "critical",
    });

    // Edges (Network, Logic, Dependencies)
    // Path 1: ep-api-gateway -> srv-order-svc -> app-payment-gateway -> db-cust-vault
    SecurityDigitalTwin.upsertEdge({
      id: "edge-apigw-ordersvc",
      tenantId: tenantA,
      sourceId: "ep-api-gateway",
      targetId: "srv-order-svc",
      relationType: "can_reach",
      port: 8443,
      protocol: "https",
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-ordersvc-payment",
      tenantId: tenantA,
      sourceId: "srv-order-svc",
      targetId: "app-payment-gateway",
      relationType: "connects_to",
      port: 9000,
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-payment-db",
      tenantId: tenantA,
      sourceId: "app-payment-gateway",
      targetId: "db-cust-vault",
      relationType: "connects_to",
      port: 5432,
    });

    // Path 2: ep-vpn-portal -> srv-bastion-host -> db-cust-vault
    SecurityDigitalTwin.upsertEdge({
      id: "edge-vpn-bastion",
      tenantId: tenantA,
      sourceId: "ep-vpn-portal",
      targetId: "srv-bastion-host",
      relationType: "can_reach",
      port: 22,
    });

    SecurityDigitalTwin.upsertEdge({
      id: "edge-bastion-db",
      tenantId: tenantA,
      sourceId: "srv-bastion-host",
      targetId: "db-cust-vault",
      relationType: "connects_to",
      port: 5432,
    });

    // Vulnerability on Order Service
    SecurityDigitalTwin.upsertEdge({
      id: "edge-order-vuln",
      tenantId: tenantA,
      sourceId: "srv-order-svc",
      targetId: "vuln-rce-spring",
      relationType: "has_vulnerability",
    });

    // Business Service depends on DB
    SecurityDigitalTwin.upsertEdge({
      id: "edge-biz-db",
      tenantId: tenantA,
      sourceId: "svc-checkout-core",
      targetId: "db-cust-vault",
      relationType: "depends_on",
    });

    // DBA manages DB
    SecurityDigitalTwin.upsertEdge({
      id: "edge-dba-db",
      tenantId: tenantA,
      sourceId: "id-dba-admin",
      targetId: "db-cust-vault",
      relationType: "authenticates_as",
    });
  }

  await t.test("AttackPathEngine: Computes ranked attack paths with explainable MITRE ATT&CK kill-chains", () => {
    seedTenantATopology();

    const report = AttackPathEngine.analyzeAttackPaths(tenantA, "db-cust-vault");

    // Must find both viable paths
    assert.equal(report.pathsFoundCount, 2);
    assert.equal(report.paths.length, 2);
    assert.ok(report.highestRiskScore !== undefined && report.highestRiskScore > 0);

    // Verify paths are ranked descending
    const path1 = report.paths[0];
    const path2 = report.paths[1];
    assert.equal(path1.rank, 1);
    assert.equal(path2.rank, 2);
    assert.ok(path1.aggregateRiskScore >= path2.aggregateRiskScore);

    // Verify explainable kill-chain fields
    assert.ok(path1.killChainSummary && path1.killChainSummary.length > 0);
    assert.ok(path1.explanation && path1.explanation.includes("Adversary begins at entry point"));
    assert.ok(path1.hopCount && path1.hopCount > 0);

    // Check step detail & MITRE ATT&CK tactics
    assert.ok(path1.steps.length >= 3);
    const entryStep = path1.steps[0];
    assert.equal(entryStep.stage, "entry_point");
    assert.equal(entryStep.mitreTactic, "Initial Access");
    assert.ok(entryStep.technique?.includes("T1190"));
    assert.ok(entryStep.rationale && entryStep.rationale.length > 0);

    // Verify business impact step is included because svc-checkout-core depends on db-cust-vault
    const bizStep = path1.steps.find((s) => s.stage === "business_impact");
    assert.ok(bizStep, "Path must include business_impact step when dependent business services exist");
    assert.equal(bizStep?.mitreTactic, "Impact");
    assert.ok(bizStep?.evidence.some((e) => e.includes("Core E-Commerce Checkout")));
  });

  await t.test("AttackPathEngine: Calculates choke-point efficacy and actionable remediation recommendations", () => {
    seedTenantATopology();

    const report = AttackPathEngine.analyzeAttackPaths(tenantA, "db-cust-vault");

    assert.ok(report.criticalChokePoints.length > 0);
    const topChokePoint = report.criticalChokePoints[0];

    assert.ok(topChokePoint.assetId);
    assert.ok(topChokePoint.assetName);
    assert.ok(topChokePoint.pathsSevered >= 1);
    assert.ok(topChokePoint.riskReductionPercentage !== undefined && topChokePoint.riskReductionPercentage > 0);
    assert.ok(topChokePoint.recommendedRemediation.includes("to neutralize"));

    // Summary must contain high-level metrics
    assert.ok(report.summary && report.summary.includes("Identified 2 viable attack path(s)"));
  });

  await t.test("AttackPathEngine: Gracefully handles unmapped target assets fail-closed", () => {
    const report = AttackPathEngine.analyzeAttackPaths(tenantA, "non-existent-asset");

    assert.equal(report.pathsFoundCount, 0);
    assert.equal(report.paths.length, 0);
    assert.equal(report.highestRiskScore, 0);
    assert.equal(report.criticalChokePoints.length, 0);
    assert.ok(report.summary && report.summary.includes("not registered"));
  });

  await t.test("BlastRadiusEngine: Evaluates multi-dimensional blast radius (services, apps, users, sensitive systems, downtime, rollback)", () => {
    seedTenantATopology();

    const report = BlastRadiusEngine.calculateBlastRadius(tenantA, "db-cust-vault", "isolate_host");

    // Target information
    assert.equal(report.targetAssetId, "db-cust-vault");
    assert.equal(report.calculationMode, "measured");
    assert.ok(report.score > 0);

    // 1. Affected Services
    assert.ok(report.affectedServices.length >= 1);
    const bizSvc = report.affectedServices.find((s) => s.name === "Core E-Commerce Checkout");
    assert.ok(bizSvc);
    assert.equal(bizSvc?.tier, "tier_1_mission_critical");

    // 2. Affected Apps
    assert.ok(report.affectedApps && report.affectedApps.length >= 1);
    const paymentApp = report.affectedApps?.find((a) => a.name === "Payment Processing Microservice");
    assert.ok(paymentApp);
    assert.equal(paymentApp?.type, "application");

    // 3. Affected Users
    assert.ok(report.affectedUsers.length >= 1);
    const dba = report.affectedUsers.find((u) => u.name === "Senior Database Administrator");
    assert.ok(dba);
    assert.equal(dba?.department, "Infrastructure & Security");

    // 4. Sensitive Systems Analysis
    assert.ok(report.sensitiveSystems);
    assert.equal(report.sensitiveSystems.detected, true);
    assert.ok(report.sensitiveSystems.categories.includes("pii"));
    assert.ok(report.sensitiveSystems.categories.includes("pci"));
    assert.ok(report.sensitiveSystems.categories.includes("crown_jewel"));

    // 5. Downtime Modeling
    assert.ok(report.estimatedDowntime.minutes >= 30);
    assert.equal(report.estimatedDowntime.severity, "major");
    assert.ok(report.estimatedDowntime.description.includes("min service disruption"));

    // 6. Rollback Availability Assessment
    assert.ok(report.rollbackAvailability);
    assert.equal(report.rollbackAvailability.available, true);
    assert.equal(report.rollbackAvailability.method, "restore_host");
    assert.equal(report.rollbackAvailability.preFlightSnapshotRequired, true);
    assert.equal(report.rollbackAvailability.reversibilityRisk, "low");
    assert.ok(report.rollbackAvailability.evidence.length > 0);

    // 7. Alternative Mitigation Options
    assert.ok(report.mitigationOptions && report.mitigationOptions.length > 0);
    const isolateOpt = report.mitigationOptions.find((m) => m.strategy === "isolate_asset");
    assert.ok(isolateOpt);
  });

  await t.test("BlastRadiusEngine: Distinguishes measured, inferred, simulated, and estimated calculation modes", () => {
    // 1. Unmapped asset -> estimated
    const unmappedReport = BlastRadiusEngine.calculateBlastRadius(tenantA, "unmapped-host-99", "isolate_host");
    assert.equal(unmappedReport.calculationMode, "estimated");
    assert.equal(unmappedReport.confidence, 0.4);
    assert.equal(unmappedReport.rollbackAvailability?.preFlightSnapshotRequired, true);

    // 2. Topology with isolated node -> simulated
    SecurityDigitalTwin.upsertNode({
      id: "isolated-srv",
      tenantId: tenantA,
      name: "Standalone Server",
      type: "server",
      criticality: "medium",
    });
    const isolatedReport = BlastRadiusEngine.calculateBlastRadius(tenantA, "isolated-srv", "isolate_host");
    assert.equal(isolatedReport.calculationMode, "simulated");
    assert.equal(isolatedReport.confidence, 0.7);

    // 3. Node with edges but no incoming dependencies -> inferred
    SecurityDigitalTwin.upsertNode({
      id: "leaf-node",
      tenantId: tenantA,
      name: "Leaf Node",
      type: "server",
      criticality: "low",
    });
    SecurityDigitalTwin.upsertEdge({
      id: "edge-leaf",
      tenantId: tenantA,
      sourceId: "isolated-srv",
      targetId: "leaf-node",
      relationType: "can_reach",
    });
    const leafReport = BlastRadiusEngine.calculateBlastRadius(tenantA, "leaf-node", "isolate_host");
    assert.ok(["inferred", "measured"].includes(leafReport.calculationMode));
  });

  await t.test("Multi-Tenant Isolation: Tenant A cannot inspect or affect Tenant B topology", () => {
    seedTenantATopology();

    // In tenantB, create a different single node
    SecurityDigitalTwin.upsertNode({
      id: "srv-healthcare-ehr",
      tenantId: tenantB,
      name: "Electronic Health Records Core",
      type: "database",
      criticality: "critical",
      metadata: { hipaa: true },
    });

    // Querying tenantA's target in tenantB scope returns 0 paths (isolated)
    const reportFromB = AttackPathEngine.analyzeAttackPaths(tenantB, "db-cust-vault");
    assert.equal(reportFromB.pathsFoundCount, 0);
    assert.equal(reportFromB.paths.length, 0);

    // Querying tenantB's target in tenantA scope returns 0 paths
    const reportFromA = AttackPathEngine.analyzeAttackPaths(tenantA, "srv-healthcare-ehr");
    assert.equal(reportFromA.pathsFoundCount, 0);
    assert.equal(reportFromA.paths.length, 0);

    // Blast radius for tenantB's asset evaluated under tenantA is estimated as unmapped
    const blastCrossTenant = BlastRadiusEngine.calculateBlastRadius(tenantA, "srv-healthcare-ehr", "isolate_host");
    assert.equal(blastCrossTenant.calculationMode, "estimated");
  });

  await t.test("Async DB Integration: analyzeAttackPathsAsync and calculateBlastRadiusAsync fall back cleanly in unit test mode", async () => {
    seedTenantATopology();

    const asyncReport = await AttackPathEngine.analyzeAttackPathsAsync(tenantA, "db-cust-vault", {
      persistReport: false,
    });
    assert.ok(asyncReport.pathsFoundCount >= 2);
    assert.ok(asyncReport.highestRiskScore !== undefined && asyncReport.highestRiskScore > 0);

    const asyncBlast = await BlastRadiusEngine.calculateBlastRadiusAsync(tenantA, "db-cust-vault", "isolate_host", {
      persistReport: false,
    });
    assert.equal(asyncBlast.targetAssetId, "db-cust-vault");
    assert.ok(asyncBlast.rollbackAvailability?.available);
  });
});
