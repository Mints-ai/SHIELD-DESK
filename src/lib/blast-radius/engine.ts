import crypto from "node:crypto";
import { SecurityDigitalTwin } from "../security-twin/digitalTwin";
import {
  BlastCalculationMode,
  BlastRadiusReport,
  SensitiveCategory,
  SensitiveSystemsAnalysis,
  RollbackAvailabilityReport,
  MitigationOption,
} from "./types";

export class BlastRadiusEngine {
  /**
   * Evaluates the blast radius of a security action against digital-twin dependency graph data,
   * clearly distinguishing measured, inferred, simulated, and estimated calculations,
   * and providing breakdown across services, apps, users, sensitive systems, downtime, and rollback availability.
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
      const isHighImpact =
        action.includes("isolate") ||
        action.includes("terminate") ||
        action.includes("reboot") ||
        action.includes("power_off");
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
        affectedAssets: [
          { id: targetAssetId, name: targetAssetId, type: "endpoint", criticality: "medium" },
        ],
        affectedServices: [],
        affectedUsers: [],
        affectedApps: [],
        sensitiveSystems: {
          detected: false,
          categories: [],
          systems: [],
        },
        rollbackAvailability: {
          available: isHighImpact,
          method: isHighImpact ? "restore_host" : "manual_only",
          estimatedRollbackMinutes: isHighImpact ? 5 : 0,
          preFlightSnapshotRequired: true,
          reversibilityRisk: "medium",
          evidence: [
            "Asset unmapped in topology; rollback availability assumes standard OS snapshot capability.",
          ],
        },
        mitigationOptions: [
          {
            strategy: "isolate_asset",
            targetAssetId,
            riskReduction: 50,
            residualBlastScore: 20,
            description: `Fallback containment for unmapped asset '${targetAssetId}' pending topology discovery.`,
          },
        ],
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

    // Applications & APIs running on or dependent on this asset
    const affectedApps = dependencies
      .filter((d) => d.type === "application" || d.type === "api")
      .map((app) => ({
        id: app.id,
        name: app.name,
        type: app.type,
        criticality: app.criticality,
        environment: app.environment,
      }));

    // Sensitive systems analysis across target and affected dependencies
    const sensitiveCategories = new Set<SensitiveCategory>();
    const sensitiveSystemsList: Array<{ id: string; name: string; reasons: string[]; criticality?: string }> = [];

    const allCheckedNodes = [targetNode, ...dependencies];
    for (const node of allCheckedNodes) {
      const reasons: string[] = [];
      const meta = node.metadata || {};
      const tags = node.tags || [];

      if (meta.storesPii || tags.includes("pii") || meta.pii) {
        sensitiveCategories.add("pii");
        reasons.push("Stores or processes personally identifiable information (PII)");
      }
      if (meta.storesPci || tags.includes("pci") || meta.pci || tags.includes("payment")) {
        sensitiveCategories.add("pci");
        reasons.push("Processes payment card data (PCI DSS scope)");
      }
      if (meta.sox || tags.includes("sox") || meta.financial) {
        sensitiveCategories.add("sox");
        reasons.push("Involved in financial reporting & audit logging (SOX 404 scope)");
      }
      if (meta.hipaa || tags.includes("hipaa") || meta.phi) {
        sensitiveCategories.add("hipaa");
        reasons.push("Houses protected health information (HIPAA scope)");
      }
      if (node.criticality === "critical" || tags.includes("crown_jewel")) {
        sensitiveCategories.add("crown_jewel");
        reasons.push("Designated crown jewel infrastructure");
      }
      if (node.environment === "production" || tags.includes("prod")) {
        sensitiveCategories.add("production_core");
        reasons.push("Part of live production customer-serving path");
      }

      if (reasons.length > 0) {
        sensitiveSystemsList.push({
          id: node.id,
          name: node.name,
          criticality: node.criticality,
          reasons,
        });
      }
    }

    const sensitiveSystems: SensitiveSystemsAnalysis = {
      detected: sensitiveSystemsList.length > 0,
      categories: Array.from(sensitiveCategories),
      systems: sensitiveSystemsList,
    };

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

    // Rollback availability assessment
    let rollbackMethod: RollbackAvailabilityReport["method"] = "restore_host";
    let rollbackMinutes = 2;
    let reversibilityRisk: RollbackAvailabilityReport["reversibilityRisk"] = "low";
    const rollbackEvidence: string[] = [];

    if (action.includes("isolate")) {
      rollbackMethod = "restore_host";
      rollbackMinutes = 2;
      reversibilityRisk = "low";
      rollbackEvidence.push(
        "Host network isolation is 100% reversible via restore_host agent command using cached firewall state."
      );
    } else if (action.includes("block") || action.includes("firewall")) {
      rollbackMethod = "revert_network_rules";
      rollbackMinutes = 1;
      reversibilityRisk = "low";
      rollbackEvidence.push("Port blocking rules can be instantaneously flushed without system reboot.");
    } else if (action.includes("restart") || action.includes("service")) {
      rollbackMethod = "restart_service";
      rollbackMinutes = 3;
      reversibilityRisk = "medium";
      rollbackEvidence.push("Service restarts depend on clean daemon state and lockfile release.");
    } else if (action.includes("patch") || action.includes("upgrade")) {
      rollbackMethod = "reinstall_package";
      rollbackMinutes = 8;
      reversibilityRisk = "medium";
      rollbackEvidence.push("Package rollback requires pre-flight package version snapshot in endpoint_snapshots.");
    } else {
      rollbackMethod = "manual_only";
      rollbackMinutes = 15;
      reversibilityRisk = "high";
      rollbackEvidence.push("Custom or unmanaged command execution requires manual operator intervention for reversion.");
    }

    rollbackEvidence.push(
      "Pre-flight snapshot capture enforced: SHA-256 hash will be recorded in endpoint_snapshots before dispatch."
    );

    const rollbackAvailability: RollbackAvailabilityReport = {
      available: rollbackMethod !== "manual_only",
      method: rollbackMethod,
      estimatedRollbackMinutes: rollbackMinutes,
      preFlightSnapshotRequired: true,
      reversibilityRisk,
      evidence: rollbackEvidence,
    };

    // Revenue impact tier
    let revenueTier: BlastRadiusReport["businessImpact"]["revenueImpactTier"] = "negligible";
    if (businessServices.some((s) => s.criticality === "critical")) {
      revenueTier = "critical";
    } else if (businessServices.length > 0 || targetNode.criticality === "high") {
      revenueTier = "high";
    } else if (targetNode.criticality === "medium") {
      revenueTier = "medium";
    }

    // Alternative mitigation strategies
    const mitigationOptions: MitigationOption[] = [
      {
        strategy: "isolate_asset",
        targetAssetId: targetNode.id,
        riskReduction: 85,
        residualBlastScore: simulation.blastRadiusScore,
        description: `Complete host network isolation of '${targetNode.name}' severing all ${simulation.severedEdgesCount} edges.`,
      },
    ];

    if (simulation.severedEdgesCount > 2) {
      mitigationOptions.push({
        strategy: "sever_chokepoint",
        targetAssetId: targetNode.id,
        riskReduction: 60,
        residualBlastScore: Math.round(simulation.blastRadiusScore * 0.4),
        description: `Sever only ingress network routes while maintaining core database/service connections to prevent downtime.`,
      });
    }

    const evidence: string[] = [
      `Digital Twin Topology: Target asset '${targetNode.name}' has ${simulation.severedEdgesCount} active graph connections.`,
      `Upstream Dependencies: ${dependencies.length} dependent asset(s) mapped [${dependencies.map((d) => d.name).join(", ") || "None"}].`,
      `Business Impact: ${businessServices.length} critical service(s) disrupted [${businessServices.map((b) => b.name).join(", ") || "None"}].`,
      `User Impact: ${authorizedIdentities.length} active identity binding(s) affected.`,
      `Sensitive Systems: ${sensitiveSystemsList.length} sensitive system(s) flagged in blast zone (${Array.from(sensitiveCategories).join(", ") || "none"}).`,
      `Rollback Readiness: Automated reversion available via '${rollbackMethod}' within ${rollbackMinutes} minute(s).`,
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
      affectedApps,
      sensitiveSystems,
      rollbackAvailability,
      mitigationOptions,
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
        regulatoryRisk: sensitiveCategories.has("pii") || sensitiveCategories.has("hipaa") ? "high" : "none",
        serviceDisruptions: businessServices.map((b) => b.name),
      },
      evidence,
      calculatedAt,
    };
  }

  /**
   * Asynchronous blast radius analysis that queries Postgres CTE queries from the
   * persistent Digital Twin graph, falling back to in-memory evaluation.
   * Can persist the report to the `blast_radius_reports` table.
   */
  public static async calculateBlastRadiusAsync(
    tenantId: string,
    targetAssetId: string,
    action: string,
    options?: { persistReport?: boolean }
  ): Promise<BlastRadiusReport> {
    let report: BlastRadiusReport;

    try {
      const { getNodeFromDB, simulateIsolationInDB } = await import(
        "../security-twin/twinDbAdapter"
      );
      const nodeRes = await getNodeFromDB(tenantId, targetAssetId);
      if (nodeRes && nodeRes.data) {
        const simRes = await simulateIsolationInDB(tenantId, targetAssetId);
        if (simRes && simRes.data) {
          // Sync DB data into memory cache so standard calculation runs with maximum richness
          SecurityDigitalTwin.upsertNode(nodeRes.data);
          report = this.calculateBlastRadius(tenantId, targetAssetId, action);
          report.calculationMode = "measured";
        } else {
          report = this.calculateBlastRadius(tenantId, targetAssetId, action);
        }
      } else {
        report = this.calculateBlastRadius(tenantId, targetAssetId, action);
      }
    } catch {
      report = this.calculateBlastRadius(tenantId, targetAssetId, action);
    }

    // Persist report if requested and DATABASE_URL is available
    if (options?.persistReport !== false && process.env.DATABASE_URL) {
      try {
        const { query } = await import("../db");
        const reportId = `brr-${crypto.randomBytes(8).toString("hex")}`;
        await query(
          `INSERT INTO blast_radius_reports
            (id, tenant_id, target_asset_id, action, score, exceeded, calculation_mode, confidence,
             affected_assets, affected_services, affected_apps, affected_users, sensitive_systems,
             estimated_downtime, rollback_availability, security_impact, business_impact, evidence, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW())
           ON CONFLICT (id) DO NOTHING`,
          [
            reportId,
            report.tenantId,
            report.targetAssetId,
            report.action,
            report.score,
            report.exceeded,
            report.calculationMode,
            report.confidence,
            JSON.stringify(report.affectedAssets),
            JSON.stringify(report.affectedServices),
            JSON.stringify(report.affectedApps || []),
            JSON.stringify(report.affectedUsers),
            JSON.stringify(report.sensitiveSystems || {}),
            JSON.stringify(report.estimatedDowntime),
            JSON.stringify(report.rollbackAvailability || {}),
            JSON.stringify(report.securityImpact),
            JSON.stringify(report.businessImpact),
            JSON.stringify(report.evidence),
          ]
        );
      } catch {
        // Logging only; persistence failure does not block the security decision
      }
    }

    return report;
  }
}
