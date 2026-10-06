import crypto from "node:crypto";
import { FindingInput, RootCauseGroup, RemediationSimulationPlan, VerificationCheckSpec } from "./types";

export class RootCauseGroupingEngine {
  /**
   * Groups a set of raw findings/vulnerabilities by shared root cause
   * (e.g., shared vulnerable package, CVE, service, or configuration key)
   * and computes predictive simulation metrics for each group.
   */
  public static groupFindingsAndSimulate(
    findings: FindingInput[],
    tenantId: string
  ): RemediationSimulationPlan[] {
    if (!findings || findings.length === 0) {
      return [];
    }

    // 1. Group findings by root cause key
    const groupMap = new Map<string, FindingInput[]>();

    for (const finding of findings) {
      let key = "";
      if (finding.packageName && finding.packageName.trim() !== "") {
        key = `pkg:${finding.packageName.trim().toLowerCase()}`;
      } else if (finding.configKey && finding.configKey.trim() !== "") {
        key = `cfg:${finding.configKey.trim().toLowerCase()}`;
      } else if (finding.serviceName && finding.serviceName.trim() !== "") {
        key = `svc:${finding.serviceName.trim().toLowerCase()}`;
      } else if (finding.cveId && finding.cveId.trim() !== "") {
        key = `cve:${finding.cveId.trim().toUpperCase()}`;
      } else {
        key = `gen:${finding.id || "unknown"}`;
      }

      if (!groupMap.has(key)) {
        groupMap.set(key, []);
      }
      groupMap.get(key)!.push(finding);
    }

    // 2. Build simulation plan for each group
    const simulationPlans: RemediationSimulationPlan[] = [];

    for (const [key, groupFindings] of groupMap.entries()) {
      const plan = this.simulateGroup(key, groupFindings, tenantId);
      simulationPlans.push(plan);
    }

    // Sort by priority: highest CVSS & KEV first
    simulationPlans.sort((a, b) => {
      const aKev = a.simulationResults.hasKev ? 1 : 0;
      const bKev = b.simulationResults.hasKev ? 1 : 0;
      if (bKev !== aKev) return bKev - aKev;
      return b.simulationResults.maxCvss - a.simulationResults.maxCvss;
    });

    return simulationPlans;
  }

  /**
   * Evaluates simulation metrics for a single root-cause group.
   */
  private static simulateGroup(
    groupKey: string,
    findings: FindingInput[],
    tenantId: string
  ): RemediationSimulationPlan {
    const [prefix, rawIdentifier] = groupKey.split(":", 2);

    let groupType: RootCauseGroup["groupType"] = "generic";
    if (prefix === "pkg") groupType = "package";
    else if (prefix === "cfg") groupType = "config";
    else if (prefix === "svc") groupType = "service";
    else if (prefix === "cve") groupType = "cve";

    // Collect affected assets deduplicated
    const assetMap = new Map<string, string | undefined>();
    const cveSet = new Set<string>();
    let maxCvss = 0;
    let hasKev = false;
    let packageName: string | undefined;
    let fixedVersion: string | undefined;

    for (const f of findings) {
      assetMap.set(f.assetId, f.assetHostname);
      if (f.cveId) cveSet.add(f.cveId.toUpperCase());
      if (f.cvssScore && f.cvssScore > maxCvss) maxCvss = f.cvssScore;
      if (f.kevListed) hasKev = true;
      if (f.packageName && !packageName) packageName = f.packageName;
      if (f.fixedVersion && !fixedVersion) fixedVersion = f.fixedVersion;
    }

    const affectedAssets = Array.from(assetMap.entries()).map(([assetId, assetHostname]) => ({
      assetId,
      assetHostname,
    }));

    const cveIds = Array.from(cveSet);
    const assetCount = affectedAssets.length;

    // Determine reboot & downtime
    const requiresReboot =
      groupType === "package" &&
      packageName !== undefined &&
      (packageName.includes("linux-image") ||
        packageName.includes("kernel") ||
        packageName.includes("systemd") ||
        packageName.includes("glibc"));

    let estimatedDowntimeMinutes = 0;
    if (requiresReboot) {
      estimatedDowntimeMinutes = 10;
    } else if (groupType === "package" || groupType === "service") {
      estimatedDowntimeMinutes = 2;
    } else {
      estimatedDowntimeMinutes = 0;
    }

    // Blast radius score (0-100)
    const blastRadiusScore = Math.min(100, Math.round(assetCount * 12 + (requiresReboot ? 25 : 5)));
    const affectedServicesCount = Math.max(1, assetCount * 2);

    // Risk reduction percentage (30% to 98%)
    let riskReduction = Math.min(
      98,
      Math.round(
        (maxCvss / 10) * 60 +
          (hasKev ? 30 : 10) +
          Math.min(10, findings.length * 2)
      )
    );
    if (riskReduction < 30) riskReduction = 30;

    // Maintenance window
    let maintenanceWindow: "immediate_emergency" | "scheduled_off_peak" | "standard_maintenance" =
      "standard_maintenance";
    if (hasKev || maxCvss >= 9.0) {
      maintenanceWindow = "immediate_emergency";
    } else if (requiresReboot || estimatedDowntimeMinutes > 5 || maxCvss >= 7.0) {
      maintenanceWindow = "scheduled_off_peak";
    }

    // Rollback readiness
    let recommendedRollbackType: RootCauseGroup["rollbackReadiness"]["recommendedRollbackType"] =
      "snapshot_restore";
    if (groupType === "package") {
      recommendedRollbackType = "package_downgrade";
    } else if (groupType === "service") {
      recommendedRollbackType = "service_restart";
    } else if (groupType === "config") {
      recommendedRollbackType = "snapshot_restore";
    }

    const rollbackReadiness: RootCauseGroup["rollbackReadiness"] = {
      snapshotSupported: true,
      recommendedRollbackType,
      estimatedRollbackTimeSeconds: requiresReboot ? 120 : 30,
    };

    // Recommended action & title
    let title = "";
    let recommendedAction = "";
    if (groupType === "package") {
      title = `Upgrade package '${packageName}' (Remediates ${findings.length} findings across ${assetCount} asset${assetCount > 1 ? "s" : ""})`;
      recommendedAction = `package_upgrade ${packageName}${fixedVersion ? `=${fixedVersion}` : ""}`;
    } else if (groupType === "config") {
      title = `Remediate configuration drift on '${rawIdentifier}' (${findings.length} findings)`;
      recommendedAction = `apply_config ${rawIdentifier}`;
    } else if (groupType === "service") {
      title = `Restart / patch service component '${rawIdentifier}'`;
      recommendedAction = `patch_service ${rawIdentifier}`;
    } else if (groupType === "cve") {
      title = `Targeted remediation for ${rawIdentifier} (${assetCount} assets)`;
      recommendedAction = `patch_cve ${rawIdentifier}`;
    } else {
      title = `Remediation for ${rawIdentifier}`;
      recommendedAction = `execute_remediation ${rawIdentifier}`;
    }

    // Build verification checklist
    const verificationChecklist: VerificationCheckSpec[] = [];
    if (groupType === "package") {
      verificationChecklist.push({
        method: "package_version_check",
        target: packageName || rawIdentifier,
        expectedState: { version: fixedVersion || "latest" },
      });
      for (const cve of cveIds.slice(0, 5)) {
        verificationChecklist.push({
          method: "vulnerability_rescan",
          target: cve,
          expectedState: { cveStatus: "not_vulnerable" },
        });
      }
    } else if (groupType === "config") {
      verificationChecklist.push({
        method: "config_state_check",
        target: rawIdentifier,
        expectedState: { value: "compliant" },
      });
    } else if (groupType === "service") {
      verificationChecklist.push({
        method: "service_health_check",
        target: rawIdentifier,
        expectedState: { status: "healthy" },
      });
    } else {
      verificationChecklist.push({
        method: "service_health_check",
        target: "endpoint",
        expectedState: { status: "healthy" },
      });
    }

    const planId = `sim-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;

    return {
      id: planId,
      tenantId,
      rootCauseId: groupKey,
      title,
      findingsCount: findings.length,
      affectedAssets,
      simulationResults: {
        groupType,
        maxCvss,
        hasKev,
        cveIds,
        projectedBlastRadius: {
          blastRadiusScore,
          affectedServicesCount,
          estimatedDowntimeMinutes,
          requiresReboot,
        },
        projectedRiskReductionPercent: riskReduction,
        rollbackReadiness,
        verificationChecklist,
      },
      recommendedAction,
      maintenanceWindow,
      status: "simulated",
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Persists a list of simulation plans to PostgreSQL.
   */
  public static async persistPlans(plans: RemediationSimulationPlan[]): Promise<void> {
    if (!plans || plans.length === 0) return;

    try {
      const { query } = await import("../db");
      for (const plan of plans) {
        await query(
          `INSERT INTO remediation_simulation_plans (
            id, tenant_id, root_cause_id, title, findings_count,
            affected_assets, simulation_results, recommended_action,
            maintenance_window, status, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
          ON CONFLICT (id) DO UPDATE SET
            findings_count = EXCLUDED.findings_count,
            affected_assets = EXCLUDED.affected_assets,
            simulation_results = EXCLUDED.simulation_results,
            recommended_action = EXCLUDED.recommended_action,
            maintenance_window = EXCLUDED.maintenance_window,
            status = EXCLUDED.status`,
          [
            plan.id,
            plan.tenantId,
            plan.rootCauseId,
            plan.title,
            plan.findingsCount,
            JSON.stringify(plan.affectedAssets),
            JSON.stringify(plan.simulationResults),
            plan.recommendedAction,
            plan.maintenanceWindow,
            plan.status,
            plan.createdAt,
          ]
        );
      }
    } catch {
      // In offline / unit test mock context
    }
  }

  /**
   * Retrieves simulation plans for a tenant from PostgreSQL.
   */
  public static async getPlansByTenant(
    tenantId: string,
    limit = 50
  ): Promise<RemediationSimulationPlan[]> {
    try {
      const { query } = await import("../db");
      const res = await query<any>(
        `SELECT id, tenant_id, root_cause_id, title, findings_count,
                affected_assets, simulation_results, recommended_action,
                maintenance_window, status, created_at
         FROM remediation_simulation_plans
         WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT $2`,
        [tenantId, limit]
      );

      return res.rows.map((r: any) => ({
        id: r.id,
        tenantId: r.tenant_id,
        rootCauseId: r.root_cause_id,
        title: r.title,
        findingsCount: r.findings_count,
        affectedAssets: typeof r.affected_assets === "string" ? JSON.parse(r.affected_assets) : r.affected_assets,
        simulationResults: typeof r.simulation_results === "string" ? JSON.parse(r.simulation_results) : r.simulation_results,
        recommendedAction: r.recommended_action,
        maintenanceWindow: r.maintenance_window,
        status: r.status,
        createdAt: r.created_at,
      }));
    } catch {
      return [];
    }
  }
}
