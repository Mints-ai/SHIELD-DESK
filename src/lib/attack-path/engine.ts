import crypto from "node:crypto";
import { SecurityDigitalTwin } from "../security-twin/digitalTwin";
import { TwinNode } from "../security-twin/types";
import { AttackPath, AttackPathAnalysisReport, AttackPathStep } from "./types";

export class AttackPathEngine {
  /**
   * Traverses the Security Digital Twin graph to identify deterministic attack paths
   * leading to the target asset, calculating choke points and tying every claim to evidence.
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
        analyzedAt,
      };
    }

    const allNodes = SecurityDigitalTwin.getNodes(tenantId);
    const edges = SecurityDigitalTwin.getEdges(tenantId);

    // Identify entry points: internet-facing, dmz, or public nodes
    const entryPoints = allNodes.filter(
      (n) =>
        n.id !== targetAssetId &&
        (n.environment === "dmz" ||
          n.tags?.includes("internet-facing") ||
          n.tags?.includes("public") ||
          n.type === "api" ||
          n.type === "endpoint")
    );

    const paths: AttackPath[] = [];

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
          let stepLikelihood = 0.8;
          const stepEvidence: string[] = [];

          if (i === 0) {
            stage = "entry_point";
            technique = "T1190 - Exploit Public-Facing Application";
            stepLikelihood = 0.75;
            stepEvidence.push(`Public-facing entry point '${srcNode.name}' (${srcNode.ipAddress || "ext"})`);
          } else if (dstNode.type === "vulnerability") {
            stage = "vulnerability";
            technique = "T1068 - Exploitation for Privilege Escalation";
            stepLikelihood = 0.9;
            stepEvidence.push(`Active vulnerability '${dstNode.name}' present on ${srcNode.name}`);
          } else if (dstNode.type === "identity" || dstNode.type === "user") {
            stage = "identity";
            technique = "T1078 - Valid Accounts";
            stepLikelihood = 0.85;
            stepEvidence.push(`Credential/identity boundary traversed: ${dstNode.name}`);
          } else if (i === nodeSequence.length - 2) {
            stage = "target";
            technique = "T1485 - Data Destruction / Impact";
            stepLikelihood = 0.95;
            stepEvidence.push(`Target asset compromised: ${dstNode.name} (${dstNode.type})`);
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
            evidence: [`Disrupts operational business services: ${bsNames}`],
            likelihood: 1.0,
            description: `Compromise of ${target.name} results in disruption to ${bsNames}`,
          });
        }

        const pathId = `ap-${crypto.createHash("sha256").update(tenantId + nodeSequence.join("->")).digest("hex").slice(0, 12)}`;
        const riskScore = Math.min(100, Math.round(runningLikelihood * 100 * (target.criticality === "critical" ? 1.0 : 0.8)));

        // Intermediate nodes act as choke points (excluding entry and target)
        const chokePoints = nodeSequence.slice(1, -1);

        paths.push({
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
        });
      }
    }

    // Determine critical choke points across all paths
    const chokeFrequency = new Map<string, number>();
    for (const p of paths) {
      for (const cp of p.chokePoints) {
        chokeFrequency.set(cp, (chokeFrequency.get(cp) || 0) + 1);
      }
    }

    const criticalChokePoints = Array.from(chokeFrequency.entries())
      .map(([assetId, count]) => {
        const node = SecurityDigitalTwin.getNode(tenantId, assetId);
        return {
          assetId,
          assetName: node?.name || assetId,
          pathsSevered: count,
          recommendedRemediation: `Isolate or remediate ${node?.name || assetId} to break ${count} active attack paths`,
        };
      })
      .sort((a, b) => b.pathsSevered - a.pathsSevered);

    return {
      tenantId,
      targetAssetId,
      pathsFoundCount: paths.length,
      paths,
      criticalChokePoints,
      analyzedAt,
    };
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

    while (queue.length > 0 && results.length < 5) {
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
