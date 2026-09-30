import { SecurityDigitalTwin } from "../security-twin/digitalTwin";
import { BlastCalculationMode, BlastRadiusReport } from "./types";

export class BlastRadiusEngine {
  /**
   * Evaluates the blast radius of a security action against real digital-twin dependency graph data,
   * clearly distinguishing measured, inferred, simulated, and estimated calculations.
   */
  public static calculateBlastRadius(
    tenantId: string,
    targetAssetId: string,
    action: string
  ): BlastRadiusReport {
    const calculatedAt = new Date().toISOString();
    const targetNode = SecurityDigitalTwin.getNode(tenantId, targetAssetId);

    // If node is not found in Digital Twin, fallback safely to estimated mode
    if (!targetNode) {
      const isHighImpact = action.includes("isolate") || action.includes("terminate") || action.includes("reboot");
      const score = isHighImpact ? 45 : 15;
      return {
        tenantId,
        targetAssetId,
        targetAssetName: targetAssetId,
        action,
        score,
        exceeded: score > 70,
        calculationMode: "estimated",
        confidence: 0.4,
        affectedAssets: [{ id: targetAssetId, name: targetAssetId, type: "endpoint", criticality: "medium" }],
        affectedServices: [],
        affectedUsers: [],
        estimatedDowntime: {
          minutes: isHighImpact ? 30 : 0,
          severity: isHighImpact ? "minimal" : "none",
          description: "Estimated downtime based on generic heuristic asset profile",
        },
        securityImpact: {
          riskReductionScore: 50,
          threatContainment: "Estimated threat containment of unmapped target asset",
          lingeringVulnerabilities: [],
        },
        businessImpact: {
          revenueImpactTier: "low",
          regulatoryRisk: "none",
          serviceDisruptions: [],
        },
        evidence: [
          `Target asset '${targetAssetId}' not registered in Security Digital Twin; heuristic estimation applied.`,
        ],
        calculatedAt,
      };
    }

    // Node is present in Digital Twin: Run real graph queries
    const simulation = SecurityDigitalTwin.simulateIsolation(tenantId, targetAssetId);
    const dependencies = SecurityDigitalTwin.getDependencies(tenantId, targetAssetId);
    const reachable = SecurityDigitalTwin.getInboundReachability(tenantId, targetAssetId);
    const businessServices = SecurityDigitalTwin.getImpactedBusinessServices(tenantId, targetAssetId);
    const authorizedIdentities = SecurityDigitalTwin.getAuthorizedIdentities(tenantId, targetAssetId);

    let mode: BlastCalculationMode = "measured";
    let confidence = 0.95;

    // If graph has partial edges
    const totalEdges = SecurityDigitalTwin.getEdges(tenantId).length;
    if (totalEdges === 0) {
      mode = "simulated";
      confidence = 0.7;
    } else if (dependencies.length === 0 && reachable.length === 0) {
      mode = "inferred";
      confidence = 0.8;
    }

    const affectedAssets = [
      { id: targetNode.id, name: targetNode.name, type: targetNode.type, criticality: targetNode.criticality },
      ...dependencies.map((d) => ({ id: d.id, name: d.name, type: d.type, criticality: d.criticality })),
    ];

    const affectedServices = businessServices.map((bs) => ({
      id: bs.id,
      name: bs.name,
      tier: bs.criticality === "critical" ? "tier_1_mission_critical" : "tier_2_standard",
    }));

    const affectedUsers = authorizedIdentities.map((u) => ({
      id: u.id,
      name: u.name,
      department: (u.metadata?.department as string) || "General",
    }));

    // Downtime estimation based on asset criticality and disrupted services
    let downtimeMinutes = 0;
    let downtimeSeverity: BlastRadiusReport["estimatedDowntime"]["severity"] = "none";

    if (action.includes("isolate") || action.includes("power_off") || action.includes("reboot")) {
      if (businessServices.some((s) => s.criticality === "critical")) {
        downtimeMinutes = 120;
        downtimeSeverity = "major";
      } else if (businessServices.length > 0) {
        downtimeMinutes = 45;
        downtimeSeverity = "moderate";
      } else if (targetNode.criticality === "critical") {
        downtimeMinutes = 30;
        downtimeSeverity = "moderate";
      } else {
        downtimeMinutes = 10;
        downtimeSeverity = "minimal";
      }
    }

    // Revenue impact tier
    let revenueTier: BlastRadiusReport["businessImpact"]["revenueImpactTier"] = "negligible";
    if (businessServices.some((s) => s.criticality === "critical")) {
      revenueTier = "critical";
    } else if (businessServices.length > 0 || targetNode.criticality === "high") {
      revenueTier = "high";
    } else if (targetNode.criticality === "medium") {
      revenueTier = "medium";
    }

    const evidence: string[] = [
      `Digital Twin Topology: Target asset '${targetNode.name}' has ${simulation.severedEdgesCount} active graph connections.`,
      `Upstream Dependencies: ${dependencies.length} dependent asset(s) mapped [${dependencies.map((d) => d.name).join(", ") || "None"}].`,
      `Business Impact: ${businessServices.length} critical service(s) disrupted [${businessServices.map((b) => b.name).join(", ") || "None"}].`,
      `User Impact: ${authorizedIdentities.length} active identity binding(s) affected.`,
    ];

    const score = simulation.blastRadiusScore;
    const exceeded = score > 70 || businessServices.some((s) => s.criticality === "critical");

    return {
      tenantId,
      targetAssetId,
      targetAssetName: targetNode.name,
      action,
      score,
      exceeded,
      calculationMode: mode,
      confidence,
      affectedAssets,
      affectedServices,
      affectedUsers,
      estimatedDowntime: {
        minutes: downtimeMinutes,
        severity: downtimeSeverity,
        description: `${action} on '${targetNode.name}' estimated to cause ${downtimeMinutes} min service disruption.`,
      },
      securityImpact: {
        riskReductionScore: Math.min(95, 40 + simulation.severedEdgesCount * 10),
        threatContainment: `Complete lateral isolation for target ${targetNode.name}`,
        lingeringVulnerabilities: SecurityDigitalTwin.getVulnerabilities(tenantId, targetAssetId).map((v) => v.name),
      },
      businessImpact: {
        revenueImpactTier: revenueTier,
        regulatoryRisk: targetNode.metadata?.storesPii ? "high" : "none",
        serviceDisruptions: businessServices.map((b) => b.name),
      },
      evidence,
      calculatedAt,
    };
  }
}
