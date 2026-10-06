/**
 * ShieldDesk Phase B — Twin Sync Pipeline
 *
 * Automatically constructs and maintains the Security Digital Twin graph
 * from Phase A security events. As events are ingested, the pipeline:
 *
 * 1. Creates or updates TwinNode for each affected asset
 * 2. Creates TwinNode for each CVE (vulnerability nodes)
 * 3. Creates TwinEdge: asset → CVE (has_vulnerability)
 * 4. Creates TwinEdge: process → asset (runs_on) from process context
 * 5. Creates TwinEdge: net src → dst (can_reach) from network context
 * 6. Persists to both in-memory twin and Postgres (dual-write)
 * 7. Records sync audit in twin_sync_log
 *
 * Dual-write contract:
 * - In-memory twin is ALWAYS written first (fast path for real-time queries).
 * - Postgres write follows synchronously. If Postgres write fails, the error
 *   is logged but does NOT roll back the in-memory write (in-memory is
 *   considered hot cache; Postgres is the durable checkpoint).
 *
 * Criticality enrichment:
 * - AssetCriticalityService.classify() is called for every asset node to
 *   populate criticality and environment from the hostname.
 *
 * NON-NEGOTIABLE: This pipeline only creates nodes and edges. It never
 * executes any commands or modifies asset state.
 */

import crypto from "node:crypto";
import { SecurityDigitalTwin } from "./digitalTwin";
import { AssetCriticalityService } from "../connectors/asset-criticality";
import type { CanonicalSecurityEvent } from "../connectors/event-model";
import type { TwinNode, TwinEdge, TwinNodeType } from "./types";

// Lazy-import db-dependent modules only when persistToDB is true.
// This avoids loading `server-only` at module resolution time so the
// tsx test runner (which shims server-only via setup.ts) can import
// TwinSyncPipeline without crashing.
async function getDbAdapter() {
  const { upsertNodeToDB, upsertEdgeToDB } = await import("./twinDbAdapter");
  const { query } = await import("../db");
  return { upsertNodeToDB, upsertEdgeToDB, query };
}

export interface SyncResult {
  tenantId: string;
  eventsProcessed: number;
  nodesUpserted: number;
  edgesUpserted: number;
  dbWriteErrors: string[];
  durationMs: number;
}

export class TwinSyncPipeline {
  /**
   * Process a batch of CanonicalSecurityEvents and sync them into the
   * Security Digital Twin (both in-memory and Postgres).
   */
  static async syncEvents(
    events: CanonicalSecurityEvent[],
    { persistToDB = false }: { persistToDB?: boolean } = {}
  ): Promise<SyncResult> {
    const start = Date.now();
    if (events.length === 0) {
      return { tenantId: "", eventsProcessed: 0, nodesUpserted: 0, edgesUpserted: 0, dbWriteErrors: [], durationMs: 0 };
    }

    const tenantId = events[0].tenantId;
    const nodesUpserted: TwinNode[] = [];
    const edgesUpserted: TwinEdge[] = [];
    const dbWriteErrors: string[] = [];

    // Lazy-load DB adapter only when persistToDB is true to avoid
    // loading `server-only` at module-resolution time in the test runner.
    const db = persistToDB ? await getDbAdapter() : null;

    for (const event of events) {
      const { nodes, edges } = this.deriveGraphObjects(event);

      for (const node of nodes) {
        SecurityDigitalTwin.upsertNode(node);
        nodesUpserted.push(node);
        if (db) {
          try {
            await db.upsertNodeToDB(node);
          } catch (err) {
            dbWriteErrors.push(`node ${node.id}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
      }

      for (const edge of edges) {
        SecurityDigitalTwin.upsertEdge(edge);
        edgesUpserted.push(edge);
        if (db) {
          try {
            await db.upsertEdgeToDB(edge);
          } catch (err) {
            dbWriteErrors.push(`edge ${edge.id}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
      }
    }

    const durationMs = Date.now() - start;

    // Record sync audit log in Postgres (best-effort)
    if (db) {
      try {
        await db.query(
          `INSERT INTO twin_sync_log (tenant_id, source, nodes_upserted, edges_upserted, duration_ms, error)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            tenantId,
            "security_event",
            nodesUpserted.length,
            edgesUpserted.length,
            durationMs,
            dbWriteErrors.length > 0 ? dbWriteErrors.join("; ") : null,
          ]
        );
      } catch {
        // sync_log write failure is non-fatal
      }
    }

    return {
      tenantId,
      eventsProcessed: events.length,
      nodesUpserted: nodesUpserted.length,
      edgesUpserted: edgesUpserted.length,
      dbWriteErrors,
      durationMs,
    };
  }

  /**
   * Derive TwinNodes and TwinEdges from a single CanonicalSecurityEvent.
   *
   * Rules (deterministic, no AI):
   * 1. Every event with an affectedAsset → one "endpoint/server/database" node
   * 2. Every vulnerability event with a cveId → one "vulnerability" node
   *    + one "has_vulnerability" edge from asset to CVE
   * 3. Process context → one "application" node + "runs_on" edge to asset
   * 4. Network context → one "can_reach" edge from srcIp node to dstIp node
   */
  static deriveGraphObjects(event: CanonicalSecurityEvent): { nodes: TwinNode[]; edges: TwinEdge[] } {
    const nodes: TwinNode[] = [];
    const edges: TwinEdge[] = [];
    const tenantId = event.tenantId;

    // ── 1. Affected asset node ──────────────────────────────────────────────
    const hostname = event.affectedAsset.hostname ?? event.affectedAsset.ip ?? "unknown-asset";
    const assetNodeId = this.stableId(`asset|${tenantId}|${hostname}`);

    const critProfile = AssetCriticalityService.classify(tenantId, hostname, event.tags);

    const assetNodeType: TwinNodeType = this.inferNodeType(hostname, event.tags);

    const assetNode: TwinNode = {
      id: assetNodeId,
      tenantId,
      name: hostname,
      type: assetNodeType,
      criticality: critProfile.criticality,
      ipAddress: event.affectedAsset.ip,
      hostname,
      tags: event.tags,
      status:
        event.severity === "critical"
          ? "compromised"
          : event.affectedAsset.criticality
          ? "healthy"
          : "healthy",
      metadata: {
        source: event.source,
        lastEventId: event.id,
        businessImpact: critProfile.businessImpact,
      },
    };
    nodes.push(assetNode);

    // ── 2. Vulnerability node + has_vulnerability edge ──────────────────────
    if (event.vulnerability?.cveId) {
      const cveId = event.vulnerability.cveId;
      const vulnNodeId = this.stableId(`vuln|${tenantId}|${cveId}`);

      const vulnNode: TwinNode = {
        id: vulnNodeId,
        tenantId,
        name: cveId,
        type: "vulnerability",
        criticality:
          event.severity === "critical"
            ? "critical"
            : event.severity === "high"
            ? "high"
            : event.severity === "medium"
            ? "medium"
            : "low",
        tags: [cveId, "vulnerability", ...(event.vulnerability.kevListed ? ["kev"] : [])],
        metadata: {
          cvssScore: event.vulnerability.cvssScore,
          cvssVector: event.vulnerability.cvssVector,
          epssScore: event.vulnerability.epssScore,
          kevListed: event.vulnerability.kevListed,
          packageName: event.vulnerability.packageName,
          installedVersion: event.vulnerability.installedVersion,
          fixedVersion: event.vulnerability.fixedVersion,
        },
      };
      nodes.push(vulnNode);

      edges.push({
        id: this.stableId(`edge|${assetNodeId}|has_vulnerability|${vulnNodeId}`),
        tenantId,
        sourceId: assetNodeId,
        targetId: vulnNodeId,
        relationType: "has_vulnerability",
        metadata: { eventId: event.id, source: event.source },
      });
    }

    // ── 3. Process context → application node + runs_on edge ───────────────
    if (event.processContext?.name) {
      const procName = event.processContext.name;
      const procNodeId = this.stableId(`proc|${tenantId}|${hostname}|${procName}`);

      const procNode: TwinNode = {
        id: procNodeId,
        tenantId,
        name: procName,
        type: "application",
        criticality: "low",
        tags: ["process", event.source],
        metadata: {
          pid: event.processContext.pid,
          commandLine: event.processContext.commandLine,
          sha256: event.processContext.sha256,
          user: event.processContext.user,
          eventId: event.id,
        },
      };
      nodes.push(procNode);

      edges.push({
        id: this.stableId(`edge|${procNodeId}|runs_on|${assetNodeId}`),
        tenantId,
        sourceId: procNodeId,
        targetId: assetNodeId,
        relationType: "runs_on",
        metadata: { eventId: event.id },
      });
    }

    // ── 4. Network context → can_reach edge ────────────────────────────────
    if (event.networkContext?.srcIp && event.networkContext?.dstIp) {
      const srcId = this.stableId(`asset|${tenantId}|${event.networkContext.srcIp}`);
      const dstId = this.stableId(`asset|${tenantId}|${event.networkContext.dstIp}`);

      // Ensure both endpoints are nodes (minimal, update-safe)
      if (!SecurityDigitalTwin.getNode(tenantId, srcId)) {
        const srcNode: TwinNode = {
          id: srcId,
          tenantId,
          name: event.networkContext.srcIp,
          type: "endpoint",
          criticality: "low",
          ipAddress: event.networkContext.srcIp,
          tags: ["network", "auto-discovered"],
        };
        nodes.push(srcNode);
      }

      edges.push({
        id: this.stableId(`edge|${srcId}|can_reach|${dstId}|${event.networkContext.dstPort ?? 0}`),
        tenantId,
        sourceId: srcId,
        targetId: dstId,
        relationType: "can_reach",
        port: event.networkContext.dstPort,
        protocol: event.networkContext.protocol,
        metadata: { eventId: event.id, source: event.source },
      });
    }

    return { nodes, edges };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Returns a stable, short node ID from an arbitrary key using SHA-256.
   * Format: "<prefix>-<first-16-hex-chars>" e.g. "nd-a1b2c3d4e5f60708"
   */
  private static stableId(key: string): string {
    return `nd-${crypto.createHash("sha256").update(key).digest("hex").slice(0, 16)}`;
  }

  /**
   * Infer TwinNodeType from hostname patterns and event tags.
   */
  private static inferNodeType(hostname: string, tags: string[]): TwinNodeType {
    const h = hostname.toLowerCase();
    if (/\b(db|database|postgres|mysql|mongo|redis|elastic)\b/.test(h)) return "database";
    if (/\b(api|gw|gateway)\b/.test(h)) return "api";
    if (/\b(web|www|nginx|apache|iis)\b/.test(h)) return "server";
    if (/\b(dc|ldap|ad)\b/.test(h)) return "server";
    if (/\b(container|docker|k8s|pod)\b/.test(h)) return "container";
    if (/\b(cloud|aws|azure|gcp|s3|bucket)\b/.test(h)) return "cloud_resource";
    if (/\b(fw|firewall|vpn|router|switch)\b/.test(h)) return "network_segment";
    if (tags.includes("endpoint") || /\b(ws|workstation|laptop|pc)\b/.test(h)) return "endpoint";
    return "server"; // safe default
  }
}
