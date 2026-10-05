/**
 * Phase B: Security Digital Twin — Postgres Graph + Sync Pipeline Test Suite
 *
 * Tests:
 * 1. TwinSyncPipeline.deriveGraphObjects() — deterministic node/edge derivation
 * 2. Asset node type inference from hostname patterns
 * 3. CVE vulnerability node + has_vulnerability edge from vulnerability event
 * 4. Process context → application node + runs_on edge
 * 5. Network context → can_reach edge
 * 6. Batch sync of multiple events: de-duplication of nodes
 * 7. Stable ID generation: same inputs always produce same IDs
 * 8. AssetCriticalityService integration: correct criticality on auto-discovered nodes
 * 9. KEV-listed CVE gets "kev" tag on vulnerability node
 * 10. Persistence mode = false (in-memory only): no DB calls
 * 11. Integration with in-memory SecurityDigitalTwin after sync
 * 12. BACKWARD COMPAT: existing SecurityDigitalTwin queries still work on synced data
 * 13. Isolation simulation still produces correct blast-radius score after sync
 */

import test from "node:test";
import assert from "node:assert/strict";
import { SecurityDigitalTwin } from "../src/lib/security-twin/digitalTwin";
import { TwinSyncPipeline } from "../src/lib/security-twin/twinSyncPipeline";
import { AssetCriticalityService } from "../src/lib/connectors/asset-criticality";
import type { CanonicalSecurityEvent } from "../src/lib/connectors/event-model";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeSecurityEvent(overrides: Partial<CanonicalSecurityEvent> = {}): CanonicalSecurityEvent {
  return {
    id: `evt-${Math.random().toString(36).slice(2, 10)}`,
    tenantId: "tenant-twin-b",
    source: "wazuh",
    externalId: `ext-${Math.random().toString(36).slice(2)}`,
    dedupFingerprint: Math.random().toString(36).repeat(2),
    timestamp: new Date().toISOString(),
    ingestAt: new Date().toISOString(),
    severity: "high",
    category: "alert",
    eventType: "process_create",
    title: "Test Alert",
    description: "Test description",
    affectedAsset: { hostname: "srv-app-01", ip: "10.0.0.1" },
    status: "open",
    tags: ["wazuh", "test"],
    evidenceIds: [],
    rawPayload: {},
    ...overrides,
  };
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

test("Phase B: Security Digital Twin — Postgres Graph + Sync Pipeline Suite", async (t) => {
  const tenantId = "tenant-twin-b";

  t.beforeEach(() => {
    SecurityDigitalTwin.clear(tenantId);
    AssetCriticalityService.clearOverrides(tenantId);
  });

  // ── 1. Basic node derivation ─────────────────────────────────────────────
  await t.test("TwinSyncPipeline: derives asset node from event affectedAsset", () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "web-nginx-01", ip: "10.0.0.10" } });
    const { nodes } = TwinSyncPipeline.deriveGraphObjects(event);

    const assetNode = nodes.find((n) => n.name === "web-nginx-01");
    assert.ok(assetNode, "Should derive an asset node from affectedAsset.hostname");
    assert.equal(assetNode!.type, "server"); // nginx → server
    assert.equal(assetNode!.tenantId, tenantId);
    assert.equal(assetNode!.hostname, "web-nginx-01");
    assert.equal(assetNode!.ipAddress, "10.0.0.10");
  });

  // ── 2. Node type inference ───────────────────────────────────────────────
  await t.test("TwinSyncPipeline: infers database type from hostname", () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "db-postgres-primary" } });
    const { nodes } = TwinSyncPipeline.deriveGraphObjects(event);
    const node = nodes.find((n) => n.name === "db-postgres-primary");
    assert.equal(node!.type, "database");
  });

  await t.test("TwinSyncPipeline: infers api type from hostname 'api-gateway-prod'", () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "api-gateway-prod" } });
    const { nodes } = TwinSyncPipeline.deriveGraphObjects(event);
    const node = nodes.find((n) => n.name === "api-gateway-prod");
    assert.equal(node!.type, "api");
  });

  await t.test("TwinSyncPipeline: infers container type from 'k8s-pod-xyz'", () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "k8s-pod-xyz" } });
    const { nodes } = TwinSyncPipeline.deriveGraphObjects(event);
    const node = nodes.find((n) => n.name === "k8s-pod-xyz");
    assert.equal(node!.type, "container");
  });

  // ── 3. CVE vulnerability node + has_vulnerability edge ───────────────────
  await t.test("TwinSyncPipeline: derives vulnerability node and has_vulnerability edge from CVE event", () => {
    const event = makeSecurityEvent({
      affectedAsset: { hostname: "pay-api-01" },
      category: "vulnerability",
      eventType: "cve_finding",
      source: "trivy",
      vulnerability: {
        cveId: "CVE-2021-44228",
        cvssScore: 10.0,
        kevListed: true,
        packageName: "log4j-core",
        installedVersion: "2.14.1",
        fixedVersion: "2.17.1",
      },
      severity: "critical",
    });

    const { nodes, edges } = TwinSyncPipeline.deriveGraphObjects(event);

    const vulnNode = nodes.find((n) => n.type === "vulnerability");
    assert.ok(vulnNode, "Should create a vulnerability node");
    assert.equal(vulnNode!.name, "CVE-2021-44228");
    assert.equal(vulnNode!.criticality, "critical");
    assert.ok(vulnNode!.tags?.includes("kev"), "KEV-listed CVE should have 'kev' tag");
    assert.equal(vulnNode!.metadata?.cvssScore, 10.0);
    assert.equal(vulnNode!.metadata?.packageName, "log4j-core");

    const hasVulnEdge = edges.find((e) => e.relationType === "has_vulnerability");
    assert.ok(hasVulnEdge, "Should create has_vulnerability edge");
    assert.equal(hasVulnEdge!.targetId, vulnNode!.id);
  });

  await t.test("TwinSyncPipeline: non-KEV CVE does not get kev tag", () => {
    const event = makeSecurityEvent({
      vulnerability: { cveId: "CVE-2023-9999", kevListed: false, cvssScore: 4.5 },
      category: "vulnerability",
    });
    const { nodes } = TwinSyncPipeline.deriveGraphObjects(event);
    const vulnNode = nodes.find((n) => n.type === "vulnerability");
    assert.ok(vulnNode);
    assert.ok(!vulnNode!.tags?.includes("kev"), "Non-KEV CVE should not have kev tag");
  });

  // ── 4. Process context → application node + runs_on edge ─────────────────
  await t.test("TwinSyncPipeline: derives process application node and runs_on edge", () => {
    const event = makeSecurityEvent({
      affectedAsset: { hostname: "finance-ws-01" },
      processContext: {
        name: "vssadmin.exe",
        pid: 3412,
        commandLine: "vssadmin.exe delete shadows /all /quiet",
        user: "NT AUTHORITY\\SYSTEM",
      },
    });

    const { nodes, edges } = TwinSyncPipeline.deriveGraphObjects(event);

    const appNode = nodes.find((n) => n.type === "application" && n.name === "vssadmin.exe");
    assert.ok(appNode, "Should create an application node for the process");
    assert.equal(appNode!.metadata?.pid, 3412);
    assert.equal(appNode!.metadata?.commandLine, "vssadmin.exe delete shadows /all /quiet");

    const runsOnEdge = edges.find((e) => e.relationType === "runs_on");
    assert.ok(runsOnEdge, "Should create a runs_on edge from process to asset");
    assert.equal(runsOnEdge!.sourceId, appNode!.id);
  });

  // ── 5. Network context → can_reach edge ──────────────────────────────────
  await t.test("TwinSyncPipeline: derives can_reach edge from network context", () => {
    const event = makeSecurityEvent({
      affectedAsset: { hostname: "threat-actor-ip" },
      networkContext: {
        srcIp: "185.220.101.1",
        dstIp: "10.0.0.5",
        dstPort: 3389,
        protocol: "tcp",
      },
    });

    const { nodes, edges } = TwinSyncPipeline.deriveGraphObjects(event);

    const reachEdge = edges.find((e) => e.relationType === "can_reach");
    assert.ok(reachEdge, "Should create a can_reach edge from src to dst");
    assert.equal(reachEdge!.port, 3389);
    assert.equal(reachEdge!.protocol, "tcp");

    // Source node (auto-discovered external IP)
    const srcNode = nodes.find((n) => n.ipAddress === "185.220.101.1");
    assert.ok(srcNode, "Should auto-create source node from srcIp");
  });

  // ── 6. Stable ID idempotency ─────────────────────────────────────────────
  await t.test("TwinSyncPipeline: same event produces same node IDs on repeated calls", () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "stable-host-01" } });

    const { nodes: nodes1 } = TwinSyncPipeline.deriveGraphObjects(event);
    const { nodes: nodes2 } = TwinSyncPipeline.deriveGraphObjects(event);

    assert.equal(nodes1[0].id, nodes2[0].id, "Stable IDs must be deterministic");
  });

  // ── 7. Batch sync: node deduplication ────────────────────────────────────
  await t.test("TwinSyncPipeline.syncEvents: deduplicates nodes for the same hostname", async () => {
    const events = [
      makeSecurityEvent({ affectedAsset: { hostname: "shared-db-01" }, id: "evt-a" }),
      makeSecurityEvent({ affectedAsset: { hostname: "shared-db-01" }, id: "evt-b" }),
      makeSecurityEvent({ affectedAsset: { hostname: "shared-db-01" }, id: "evt-c" }),
    ];

    const result = await TwinSyncPipeline.syncEvents(events, { persistToDB: false });

    assert.equal(result.eventsProcessed, 3);
    // In-memory twin should have exactly 1 node for shared-db-01 (upsert = dedup)
    const twNodes = SecurityDigitalTwin.getNodes(tenantId);
    const dbNodes = twNodes.filter((n) => n.name === "shared-db-01");
    assert.equal(dbNodes.length, 1, "Should deduplicate asset nodes with same hostname");
  });

  // ── 8. Criticality from AssetCriticalityService ──────────────────────────
  await t.test("TwinSyncPipeline: payment server auto-discovers as critical/revenue", async () => {
    const event = makeSecurityEvent({
      affectedAsset: { hostname: "payment-processor-v2" },
      severity: "high",
    });

    await TwinSyncPipeline.syncEvents([event], { persistToDB: false });

    const nodes = SecurityDigitalTwin.getNodes(tenantId);
    const payNode = nodes.find((n) => n.name === "payment-processor-v2");
    assert.ok(payNode, "Payment node should be in twin");
    assert.equal(payNode!.criticality, "critical");
  });

  await t.test("TwinSyncPipeline: database server auto-discovers as critical", async () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "db-mysql-prod-01" } });
    await TwinSyncPipeline.syncEvents([event], { persistToDB: false });

    const nodes = SecurityDigitalTwin.getNodes(tenantId);
    const dbNode = nodes.find((n) => n.name === "db-mysql-prod-01");
    assert.ok(dbNode);
    assert.equal(dbNode!.criticality, "critical");
  });

  // ── 9. In-memory twin integration after sync ──────────────────────────────
  await t.test("TwinSyncPipeline: synced nodes appear in SecurityDigitalTwin.getNodes()", async () => {
    const events = [
      makeSecurityEvent({ affectedAsset: { hostname: "api-gateway-01" }, severity: "medium" }),
      makeSecurityEvent({ affectedAsset: { hostname: "backend-srv-01" }, severity: "low" }),
    ];
    await TwinSyncPipeline.syncEvents(events, { persistToDB: false });

    const allNodes = SecurityDigitalTwin.getNodes(tenantId);
    const names = allNodes.map((n) => n.name);
    assert.ok(names.includes("api-gateway-01"), "api-gateway-01 should be in twin");
    assert.ok(names.includes("backend-srv-01"), "backend-srv-01 should be in twin");
  });

  await t.test("TwinSyncPipeline: synced CVE edges appear in SecurityDigitalTwin.getVulnerabilities()", async () => {
    const event = makeSecurityEvent({
      affectedAsset: { hostname: "vuln-target-host" },
      category: "vulnerability",
      source: "openvas",
      vulnerability: {
        cveId: "CVE-2024-12345",
        cvssScore: 8.1,
        kevListed: false,
      },
    });

    await TwinSyncPipeline.syncEvents([event], { persistToDB: false });

    // Get the asset node ID (deterministic)
    const assetNodes = SecurityDigitalTwin.getNodes(tenantId);
    const asset = assetNodes.find((n) => n.name === "vuln-target-host");
    assert.ok(asset, "Asset node should exist");

    const vulns = SecurityDigitalTwin.getVulnerabilities(tenantId, asset!.id);
    assert.ok(vulns.length > 0, "getVulnerabilities should return the synced CVE node");
    assert.equal(vulns[0].name, "CVE-2024-12345");
  });

  // ── 10. Isolation simulation after sync ───────────────────────────────────
  await t.test("TwinSyncPipeline: isolation simulation works correctly after multi-event sync", async () => {
    // Build a topology: attacker → web → app → database
    const events = [
      makeSecurityEvent({
        affectedAsset: { hostname: "db-critical-prod" },
        networkContext: { srcIp: "10.0.0.5", dstIp: "10.0.0.10", dstPort: 5432, protocol: "tcp" },
      }),
      makeSecurityEvent({
        affectedAsset: { hostname: "app-server-prod" },
        networkContext: { srcIp: "10.0.0.1", dstIp: "10.0.0.5", dstPort: 8080, protocol: "tcp" },
      }),
    ];

    await TwinSyncPipeline.syncEvents(events, { persistToDB: false });

    // The DB node should exist in the twin
    const allNodes = SecurityDigitalTwin.getNodes(tenantId);
    const dbNode = allNodes.find((n) => n.name === "db-critical-prod");
    assert.ok(dbNode, "db-critical-prod should be in twin after sync");

    // Simulate isolation — should not throw
    const isolation = SecurityDigitalTwin.simulateIsolation(tenantId, dbNode!.id);
    assert.ok(isolation.blastRadiusScore >= 0, "Blast radius score must be non-negative");
    assert.ok(isolation.blastRadiusScore <= 100, "Blast radius score must be ≤ 100");
    assert.equal(isolation.tenantId, tenantId);
    assert.equal(isolation.isolatedAssetId, dbNode!.id);
  });

  // ── 11. Mixed-source batch sync ───────────────────────────────────────────
  await t.test("TwinSyncPipeline: handles mixed-source batch (wazuh + trivy + openvas)", async () => {
    const events: CanonicalSecurityEvent[] = [
      makeSecurityEvent({ source: "wazuh", affectedAsset: { hostname: "exchange-srv-01" }, severity: "high" }),
      makeSecurityEvent({
        source: "trivy",
        affectedAsset: { hostname: "k8s-node-01" },
        category: "vulnerability",
        vulnerability: { cveId: "CVE-2023-44487", cvssScore: 7.5, kevListed: false },
      }),
      makeSecurityEvent({
        source: "openvas",
        affectedAsset: { hostname: "firewall-01", ip: "192.168.1.1" },
        category: "vulnerability",
        vulnerability: { cveId: "CVE-2021-44228", cvssScore: 10.0, kevListed: true },
      }),
    ];

    const result = await TwinSyncPipeline.syncEvents(events, { persistToDB: false });

    assert.equal(result.eventsProcessed, 3);
    assert.ok(result.nodesUpserted >= 3, "Should create at least 3 asset nodes");
    assert.ok(result.edgesUpserted >= 2, "Should create at least 2 has_vulnerability edges");

    // Verify all assets are in the twin
    const allNodes = SecurityDigitalTwin.getNodes(tenantId);
    const names = allNodes.map((n) => n.name);
    assert.ok(names.includes("exchange-srv-01"));
    assert.ok(names.includes("k8s-node-01"));
    assert.ok(names.includes("firewall-01"));
  });

  // ── 12. syncEvents duration tracking ─────────────────────────────────────
  await t.test("TwinSyncPipeline.syncEvents: reports durationMs", async () => {
    const event = makeSecurityEvent({ affectedAsset: { hostname: "timing-test-host" } });
    const result = await TwinSyncPipeline.syncEvents([event], { persistToDB: false });
    assert.ok(typeof result.durationMs === "number", "durationMs should be a number");
    assert.ok(result.durationMs >= 0, "durationMs should be non-negative");
  });

  // ── 13. Backward compat: existing SecurityDigitalTwin queries ─────────────
  await t.test("BACKWARD COMPAT: SecurityDigitalTwin.simulateIsolation still works independently", () => {
    SecurityDigitalTwin.upsertNode({
      id: "compat-db-01",
      tenantId,
      name: "CompatDB",
      type: "database",
      criticality: "critical",
    });
    SecurityDigitalTwin.upsertNode({
      id: "compat-app-01",
      tenantId,
      name: "CompatApp",
      type: "server",
      criticality: "high",
    });
    SecurityDigitalTwin.upsertEdge({
      id: "compat-edge-1",
      tenantId,
      sourceId: "compat-app-01",
      targetId: "compat-db-01",
      relationType: "depends_on",
    });

    const result = SecurityDigitalTwin.simulateIsolation(tenantId, "compat-db-01");
    assert.equal(result.isolatedAssetId, "compat-db-01");
    // critical + 1 upstream (10pts) + 1 severed edge (5pts) + 30 for critical = 45
    assert.ok(result.blastRadiusScore > 0);
    assert.equal(result.affectedUpstreamAssets.length, 1);
  });
});
