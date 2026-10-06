import crypto from "node:crypto";
import { SecurityDigitalTwin } from "../security-twin/digitalTwin";
import { TwinNode } from "../security-twin/types";
import {
  AttackPath,
  AttackPathAnalysisReport,
  AttackPathStep,
  CriticalChokePoint,
} from "./types";

export class AttackPathEngine {
  /**
   * Traverses the Security Digital Twin graph to identify deterministic attack paths
   * leading to the target asset, calculating ranked kill chains, choke points, and tying every claim to evidence.
   */
  public static analyzeAttackPaths(
    tenantId: string,
    targetAssetId: string
  ): AttackPathAnalysisReport {
    const analyzedAt = new Date().toISOString();
    const target = SecurityDigitalTwin.getNode(tenantId, targetAssetId);
    if (!target) {
      return {
        tenantId,
        targetAssetId,
        pathsFoundCount: 0,
        paths: [],
        criticalChokePoints: [],
        highestRiskScore: 0,
        summary: `Target asset '${targetAssetId}' not registered in Security Digital Twin. No attack paths found.`,
        chokePointEfficacy: [],
        analyzedAt,
      };
    }

    const allNodes = SecurityDigitalTwin.getNodes(tenantId);
    const edges = SecurityDigitalTwin.getEdges(tenantId);

    // Identify entry points: internet-facing, dmz, public nodes, or API endpoints
    const entryPoints = allNodes.filter(
      (n) =>
        n.id !== targetAssetId &&
        (n.environment === "dmz" ||
          n.tags?.includes("internet-facing") ||
          n.tags?.includes("public") ||
          n.type === "api" ||
          n.type === "endpoint")
    );

    const rawPaths: AttackPath[] = [];

    for (const ep of entryPoints) {
      // Find paths from ep to target using BFS / path search (max depth 6)
      const foundPaths = this.findPaths(tenantId, ep.id, targetAssetId, edges, 6);

      for (const nodeSequence of foundPaths) {
        const steps: AttackPathStep[] = [];
        const pathEvidence: string[] = [];
        let runningLikelihood = 1.0;

        for (let i = 0; i < nodeSequence.length - 1; i++) {
          const srcId = nodeSequence[i];
          const dstId = nodeSequence[i + 1];
          const srcNode = SecurityDigitalTwin.getNode(tenantId, srcId);
          const dstNode = SecurityDigitalTwin.getNode(tenantId, dstId);
          if (!srcNode || !dstNode) continue;

          // Find connecting edge
          const edge = edges.find(
            (e) =>
              (e.sourceId === srcId && e.targetId === dstId) ||
              (e.bidirectional && e.sourceId === dstId && e.targetId === srcId)
          );

          // Get vulnerabilities on srcNode or dstNode
          const vulns = SecurityDigitalTwin.getVulnerabilities(tenantId, srcNode.id);
          const vulnNames = vulns.map((v) => v.name);

          let stage: AttackPathStep["stage"] = "lateral_movement";
          let technique = "T1021 - Remote Services";
          let mitreTactic = "Lateral Movement";
          let stepLikelihood = 0.8;
          const stepEvidence: string[] = [];
          let rationale = `Pivots from ${srcNode.name} to ${dstNode.name} across internal network trust boundaries.`;

          if (i === 0) {
            stage = "entry_point";
            technique = "T1190 - Exploit Public-Facing Application";
            mitreTactic = "Initial Access";
            stepLikelihood = 0.75;
            stepEvidence.push(`Public-facing entry point '${srcNode.name}' (${srcNode.ipAddress || "external-facing"})`);
            rationale = `Initial compromise of perimeter asset '${srcNode.name}' via exposed network attack surface.`;
          } else if (dstNode.type === "vulnerability") {
            stage = "vulnerability";
            technique = "T1068 - Exploitation for Privilege Escalation";
            mitreTactic = "Privilege Escalation";
            stepLikelihood = 0.9;
            stepEvidence.push(`Active vulnerability '${dstNode.name}' present on ${srcNode.name}`);
            rationale = `Exploitation of unpatched flaw '${dstNode.name}' to elevate execution privileges.`;
          } else if (dstNode.type === "identity" || dstNode.type === "user") {
            stage = "identity";
            technique = "T1078 - Valid Accounts";
            mitreTactic = "Credential Access";
            stepLikelihood = 0.85;
            stepEvidence.push(`Credential/identity boundary traversed: ${dstNode.name}`);
            rationale = `Compromised credentials or authorization tokens abused to impersonate ${dstNode.name}.`;
          } else if (i === nodeSequence.length - 2) {
            stage = "target";
            technique = "T1485 - Data Destruction / Impact";
            mitreTactic = "Impact";
            stepLikelihood = 0.95;
            stepEvidence.push(`Target asset reached: ${dstNode.name} (${dstNode.type})`);
            rationale = `Threat actor establishes direct access to crown jewel target '${dstNode.name}'.`;
          }

          if (vulnNames.length > 0) {
            stepEvidence.push(`Known CVEs: ${vulnNames.join(", ")}`);
          }
          if (edge) {
            stepEvidence.push(
              `Network/Logic edge '${edge.relationType}' via port ${edge.port || "default"}`
            );
          }

          pathEvidence.push(...stepEvidence);
          runningLikelihood *= stepLikelihood;

          steps.push({
            stepIndex: i + 1,
            stage,
            sourceAssetId: srcNode.id,
            sourceAssetName: srcNode.name,
            targetAssetId: dstNode.id,
            targetAssetName: dstNode.name,
            technique,
            mitreTactic,
            rationale,
            port: edge?.port,
            protocol: edge?.protocol,
            evidence: stepEvidence,
            likelihood: Number(stepLikelihood.toFixed(2)),
            description: `${srcNode.name} -> ${dstNode.name} via ${edge?.relationType || "connectivity"}`,
          });
        }

        // Add business impact step if target has dependent business services
        const businessServices = SecurityDigitalTwin.getImpactedBusinessServices(tenantId, targetAssetId);
        if (businessServices.length > 0) {
          const bsNames = businessServices.map((b) => b.name).join(", ");
          pathEvidence.push(`Impacts business services: ${bsNames}`);
          steps.push({
            stepIndex: steps.length + 1,
            stage: "business_impact",
            sourceAssetId: target.id,
            sourceAssetName: target.name,
            targetAssetId: businessServices[0].id,
            targetAssetName: businessServices[0].name,
            technique: "T1499 - Endpoint DoS / Service Disruption",
            mitreTactic: "Impact",
            rationale: `Breach of ${target.name} propagates service failure to dependent core business application.`,
            evidence: [`Disrupts operational business services: ${bsNames}`],
            likelihood: 1.0,
            description: `Compromise of ${target.name} results in disruption to ${bsNames}`,
          });
        }

        const pathId = `ap-${crypto.createHash("sha256").update(tenantId + nodeSequence.join("->")).digest("hex").slice(0, 12)}`;
        const criticalityWeight =
          target.criticality === "critical"
            ? 1.0
            : target.criticality === "high"
            ? 0.85
            : target.criticality === "medium"
            ? 0.7
            : 0.5;

        const riskScore = Math.min(
          100,
          Math.round(runningLikelihood * 100 * criticalityWeight)
        );

        // Intermediate nodes act as choke points (excluding entry and target)
        const chokePoints = nodeSequence.slice(1, -1);

        const tacticsSummary = Array.from(new Set(steps.map((s) => s.technique ? s.technique.split(" - ")[1] || s.technique : s.stage))).join(" → ");
        const explanation = `Adversary begins at entry point '${ep.name}' (${ep.type}), transitions across ${steps.length} distinct hops (${tacticsSummary}), ultimately reaching target '${target.name}'.`;

        rawPaths.push({
          pathId,
          tenantId,
          targetAssetId,
          targetAssetName: target.name,
          entryPointAssetId: ep.id,
          entryPointAssetName: ep.name,
          steps,
          totalLikelihood: Number(runningLikelihood.toFixed(3)),
          aggregateRiskScore: riskScore,
          chokePoints,
          evidence: Array.from(new Set(pathEvidence)),
          killChainSummary: tacticsSummary,
          explanation,
          hopCount: steps.length,
        });
      }
    }

    // Sort paths by aggregateRiskScore descending to establish rank
    const paths = rawPaths
      .sort((a, b) => b.aggregateRiskScore - a.aggregateRiskScore)
      .map((p, idx) => ({
        ...p,
        rank: idx + 1,
      }));

    // Determine critical choke points across all paths
    const chokeFrequency = new Map<string, number>();
    for (const p of paths) {
      for (const cp of p.chokePoints) {
        chokeFrequency.set(cp, (chokeFrequency.get(cp) || 0) + 1);
      }
    }

    const totalPathsCount = paths.length;
    const criticalChokePoints: CriticalChokePoint[] = Array.from(chokeFrequency.entries())
      .map(([assetId, count]) => {
        const node = SecurityDigitalTwin.getNode(tenantId, assetId);
        const reductionPct = totalPathsCount > 0 ? Math.round((count / totalPathsCount) * 100) : 0;
        return {
          assetId,
          assetName: node?.name || assetId,
          pathsSevered: count,
          riskReductionPercentage: reductionPct,
          recommendedRemediation: `Isolate or harden '${node?.name || assetId}' to neutralize ${count} of ${totalPathsCount} (${reductionPct}%) viable attack paths.`,
        };
      })
      .sort((a, b) => b.pathsSevered - a.pathsSevered);

    const highestRiskScore = paths.length > 0 ? paths[0].aggregateRiskScore : 0;
    const summary =
      paths.length > 0
        ? `Identified ${paths.length} viable attack path(s) originating from ${entryPoints.length} exposed entry point(s). Highest risk score: ${highestRiskScore}/100. Top choke point '${criticalChokePoints[0]?.assetName || "N/A"}' neutralizes ${criticalChokePoints[0]?.riskReductionPercentage || 0}% of threats.`
        : `No viable attack paths found connecting registered entry points to target '${target.name}'.`;

    return {
      tenantId,
      targetAssetId,
      pathsFoundCount: paths.length,
      paths,
      criticalChokePoints,
      highestRiskScore,
      summary,
      chokePointEfficacy: criticalChokePoints,
      analyzedAt,
    };
  }

  /**
   * Asynchronous attack path analysis that attempts to leverage Postgres CTE queries
   * and persistent Digital Twin graph data, falling back cleanly to in-memory traversal.
   * Can persist the analysis report to the `attack_path_reports` table.
   */
  public static async analyzeAttackPathsAsync(
    tenantId: string,
    targetAssetId: string,
    options?: { maxDepth?: number; persistReport?: boolean }
  ): Promise<AttackPathAnalysisReport> {
    const maxDepth = options?.maxDepth ?? 6;
    let report: AttackPathAnalysisReport;

    try {
      const { getNodeFromDB, getEdgesFromDB, findAttackPathsFromDB } = await import(
        "../security-twin/twinDbAdapter"
      );
      // First attempt DB-backed traversal
      const targetRes = await getNodeFromDB(tenantId, targetAssetId);
      if (targetRes && targetRes.data) {
        const dbPathsRes = await findAttackPathsFromDB(tenantId, targetAssetId, maxDepth);
        if (dbPathsRes && dbPathsRes.data && dbPathsRes.data.length > 0) {
          // Reconstruct paths from DB
          const target = targetRes.data;
          const edgesRes = await getEdgesFromDB(tenantId);
          const allEdges = edgesRes.data || [];

          const constructedPaths: AttackPath[] = [];
          for (const item of dbPathsRes.data) {
            const nodeSeq = item.path;
            const steps: AttackPathStep[] = [];
            const pathEvidence: string[] = [];
            let runningLikelihood = 1.0;

            const epNodeRes = await getNodeFromDB(tenantId, nodeSeq[0]);
            const epNode = epNodeRes.data;

            for (let i = 0; i < nodeSeq.length - 1; i++) {
              const srcId = nodeSeq[i];
              const dstId = nodeSeq[i + 1];
              const srcNodeRes = await getNodeFromDB(tenantId, srcId);
              const dstNodeRes = await getNodeFromDB(tenantId, dstId);
              const srcNode = srcNodeRes.data;
              const dstNode = dstNodeRes.data;
              if (!srcNode || !dstNode) continue;

              const edge = allEdges.find(
                (e) =>
                  (e.sourceId === srcId && e.targetId === dstId) ||
                  (e.bidirectional && e.sourceId === dstId && e.targetId === srcId)
              );

              let stage: AttackPathStep["stage"] = "lateral_movement";
              let technique = "T1021 - Remote Services";
              let mitreTactic = "Lateral Movement";
              let stepLikelihood = 0.8;
              const stepEvidence: string[] = [];

              if (i === 0) {
                stage = "entry_point";
                technique = "T1190 - Exploit Public-Facing Application";
                mitreTactic = "Initial Access";
                stepLikelihood = 0.75;
                stepEvidence.push(`Public-facing entry point '${srcNode.name}' (${srcNode.ipAddress || "ext"})`);
              } else if (dstNode.type === "vulnerability") {
                stage = "vulnerability";
                technique = "T1068 - Exploitation for Privilege Escalation";
                mitreTactic = "Privilege Escalation";
                stepLikelihood = 0.9;
                stepEvidence.push(`Vulnerability present on ${srcNode.name}`);
              } else if (i === nodeSeq.length - 2) {
                stage = "target";
                technique = "T1485 - Data Destruction / Impact";
                mitreTactic = "Impact";
                stepLikelihood = 0.95;
                stepEvidence.push(`Target asset compromised: ${dstNode.name}`);
              }

              if (edge) {
                stepEvidence.push(`Edge '${edge.relationType}' via port ${edge.port || "default"}`);
              }

              pathEvidence.push(...stepEvidence);
              runningLikelihood *= stepLikelihood;

              steps.push({
                stepIndex: i + 1,
                stage,
                sourceAssetId: srcNode.id,
                sourceAssetName: srcNode.name,
                targetAssetId: dstNode.id,
                targetAssetName: dstNode.name,
                technique,
                mitreTactic,
                rationale: `${srcNode.name} -> ${dstNode.name}`,
                port: edge?.port,
                protocol: edge?.protocol,
                evidence: stepEvidence,
                likelihood: Number(stepLikelihood.toFixed(2)),
                description: `${srcNode.name} -> ${dstNode.name} via ${edge?.relationType || "connectivity"}`,
              });
            }

            const pathId = `ap-${crypto.createHash("sha256").update(tenantId + nodeSeq.join("->")).digest("hex").slice(0, 12)}`;
            const riskScore = Math.min(
              100,
              Math.round(runningLikelihood * 100 * (target.criticality === "critical" ? 1.0 : 0.85))
            );

            constructedPaths.push({
              pathId,
              tenantId,
              targetAssetId,
              targetAssetName: target.name,
              entryPointAssetId: epNode?.id || nodeSeq[0],
              entryPointAssetName: epNode?.name || nodeSeq[0],
              steps,
              totalLikelihood: Number(runningLikelihood.toFixed(3)),
              aggregateRiskScore: riskScore,
              chokePoints: nodeSeq.slice(1, -1),
              evidence: Array.from(new Set(pathEvidence)),
              killChainSummary: steps.map((s) => s.technique || s.stage).join(" → "),
              explanation: `Adversary reaches target '${target.name}' from '${epNode?.name || nodeSeq[0]}' through ${steps.length} hops.`,
              hopCount: steps.length,
            });
          }

          constructedPaths.sort((a, b) => b.aggregateRiskScore - a.aggregateRiskScore);
          constructedPaths.forEach((p, i) => {
            p.rank = i + 1;
          });

          const chokeFreq = new Map<string, number>();
          for (const p of constructedPaths) {
            for (const cp of p.chokePoints) {
              chokeFreq.set(cp, (chokeFreq.get(cp) || 0) + 1);
            }
          }

          const criticalChokePoints: CriticalChokePoint[] = [];
          for (const [assetId, count] of chokeFreq.entries()) {
            const nRes = await getNodeFromDB(tenantId, assetId);
            const nName = nRes.data?.name || assetId;
            const pct = Math.round((count / constructedPaths.length) * 100);
            criticalChokePoints.push({
              assetId,
              assetName: nName,
              pathsSevered: count,
              riskReductionPercentage: pct,
              recommendedRemediation: `Isolate '${nName}' to sever ${count} attack path(s) (${pct}% reduction).`,
            });
          }

          report = {
            tenantId,
            targetAssetId,
            pathsFoundCount: constructedPaths.length,
            paths: constructedPaths,
            criticalChokePoints,
            highestRiskScore: constructedPaths.length > 0 ? constructedPaths[0].aggregateRiskScore : 0,
            summary: `Discovered ${constructedPaths.length} attack path(s) via persistent Digital Twin CTE queries.`,
            chokePointEfficacy: criticalChokePoints,
            analyzedAt: new Date().toISOString(),
          };
        } else {
          // Fall back to in-memory twin
          report = this.analyzeAttackPaths(tenantId, targetAssetId);
        }
      } else {
        // Fall back to in-memory twin
        report = this.analyzeAttackPaths(tenantId, targetAssetId);
      }
    } catch {
      // Clean fallback if DB throws or connection fails
      report = this.analyzeAttackPaths(tenantId, targetAssetId);
    }

    // Persist report if requested and DATABASE_URL is available
    if (options?.persistReport !== false && process.env.DATABASE_URL) {
      try {
        const { query } = await import("../db");
        const reportId = `apr-${crypto.randomBytes(8).toString("hex")}`;
        await query(
          `INSERT INTO attack_path_reports
            (id, tenant_id, target_asset_id, paths_found_count, highest_risk_score, critical_choke_points, paths, summary, analyzed_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO NOTHING`,
          [
            reportId,
            report.tenantId,
            report.targetAssetId,
            report.pathsFoundCount,
            report.highestRiskScore || 0,
            JSON.stringify(report.criticalChokePoints),
            JSON.stringify(report.paths),
            report.summary || "",
            report.analyzedAt,
          ]
        );
      } catch {
        // Logging only; persistence failure does not block the security decision
      }
    }

    return report;
  }

  private static findPaths(
    tenantId: string,
    startId: string,
    targetId: string,
    edges: Array<{ sourceId: string; targetId: string; bidirectional?: boolean }>,
    maxDepth: number
  ): string[][] {
    const results: string[][] = [];
    const queue: Array<{ current: string; path: string[] }> = [{ current: startId, path: [startId] }];

    while (queue.length > 0 && results.length < 10) {
      const { current, path } = queue.shift()!;
      if (current === targetId) {
        results.push(path);
        continue;
      }
      if (path.length >= maxDepth) continue;

      // Find neighbors
      const neighbors: string[] = [];
      for (const e of edges) {
        if (e.sourceId === current && !path.includes(e.targetId)) {
          neighbors.push(e.targetId);
        } else if (e.bidirectional && e.targetId === current && !path.includes(e.sourceId)) {
          neighbors.push(e.sourceId);
        }
      }

      for (const n of neighbors) {
        queue.push({ current: n, path: [...path, n] });
      }
    }

    return results;
  }
}
