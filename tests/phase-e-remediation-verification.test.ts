/**
 * Phase E: Remediation Simulator & Verification Engine Test Suite
 *
 * Verifies:
 * 1. Root-cause grouping across bulk CVE findings (package, CVE, config, service)
 * 2. Predictive remediation simulation (blast radius, risk reduction, downtime window, maintenance window)
 * 3. Deterministic verification methods (process table, firewall, package version, service health, config state, port)
 * 4. Proof Before Action: Never claim success without verification
 * 5. Closed-loop fail-closed path: Failed verification triggers automated rollback, reopens finding, and records audit trail
 * 6. Continuous recheck scheduler and drift detection for closed findings
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  RootCauseGroupingEngine,
  VerificationEngine,
  VerificationMethods,
  ContinuousRecheckService,
  FindingInput,
  VerificationCheckSpec,
} from "../src/lib/verification-engine";

test("Phase E: Remediation Simulator & Verification Engine Suite", async (t) => {
  const tenantId = "tenant-cyber-ops";

  // =========================================================================
  // 1. Root-Cause Grouping Engine
  // =========================================================================
  await t.test("RootCauseGrouping: Groups raw CVEs by shared vulnerable package", () => {
    const rawFindings: FindingInput[] = [
      {
        id: "vuln-1",
        cveId: "CVE-2023-0286",
        packageName: "openssl",
        installedVersion: "1.1.1n",
        fixedVersion: "1.1.1t",
        assetId: "ast-srv-web01",
        assetHostname: "web01.corp",
        cvssScore: 7.4,
        kevListed: false,
      },
      {
        id: "vuln-2",
        cveId: "CVE-2023-0401",
        packageName: "openssl",
        installedVersion: "1.1.1n",
        fixedVersion: "1.1.1t",
        assetId: "ast-srv-web01",
        assetHostname: "web01.corp",
        cvssScore: 5.3,
        kevListed: false,
      },
      {
        id: "vuln-3",
        cveId: "CVE-2024-0553",
        packageName: "openssl",
        installedVersion: "1.1.1n",
        fixedVersion: "1.1.1t",
        assetId: "ast-srv-web02",
        assetHostname: "web02.corp",
        cvssScore: 8.1,
        kevListed: true,
      },
      {
        id: "vuln-4",
        configKey: "PermitRootLogin",
        assetId: "ast-srv-db01",
        assetHostname: "db01.corp",
        cvssScore: 6.5,
      },
    ];

    const plans = RootCauseGroupingEngine.groupFindingsAndSimulate(rawFindings, tenantId);

    // Should create 2 distinct root-cause groups (openssl package + PermitRootLogin config)
    assert.equal(plans.length, 2);

    const opensslPlan = plans.find((p) => p.rootCauseId === "pkg:openssl");
    assert.ok(opensslPlan);
    assert.equal(opensslPlan.findingsCount, 3);
    assert.equal(opensslPlan.affectedAssets.length, 2); // web01 and web02
    assert.equal(opensslPlan.simulationResults.hasKev, true);
    assert.equal(opensslPlan.simulationResults.maxCvss, 8.1);
    assert.ok(opensslPlan.simulationResults.cveIds.includes("CVE-2024-0553"));

    // Check prioritization: Plan with KEV and higher CVSS is ranked first
    assert.equal(plans[0].rootCauseId, "pkg:openssl");
  });

  // =========================================================================
  // 2. Predictive Remediation Simulation
  // =========================================================================
  await t.test("Remediation Simulation: Models downtime, reboot requirement, and maintenance windows", () => {
    // Scenario A: Kernel package (requires reboot, scheduled off-peak, longer downtime)
    const kernelFindings: FindingInput[] = [
      {
        id: "vuln-kernel",
        cveId: "CVE-2024-1086",
        packageName: "linux-image-generic",
        assetId: "ast-srv-core",
        assetHostname: "core.corp",
        cvssScore: 7.8,
        kevListed: false,
      },
    ];
    const kernelPlans = RootCauseGroupingEngine.groupFindingsAndSimulate(kernelFindings, tenantId);
    assert.equal(kernelPlans.length, 1);
    const kp = kernelPlans[0];
    assert.equal(kp.simulationResults.projectedBlastRadius.requiresReboot, true);
    assert.equal(kp.simulationResults.projectedBlastRadius.estimatedDowntimeMinutes, 10);
    assert.equal(kp.maintenanceWindow, "scheduled_off_peak");

    // Scenario B: Critical Emergency CVE (KEV listed -> immediate_emergency)
    const emergencyFindings: FindingInput[] = [
      {
        id: "vuln-emer",
        cveId: "CVE-2024-3400",
        packageName: "panos-gateway",
        assetId: "ast-fw-01",
        assetHostname: "fw01.corp",
        cvssScore: 10.0,
        kevListed: true,
      },
    ];
    const emerPlans = RootCauseGroupingEngine.groupFindingsAndSimulate(emergencyFindings, tenantId);
    assert.equal(emerPlans[0].maintenanceWindow, "immediate_emergency");
    assert.ok(emerPlans[0].simulationResults.projectedRiskReductionPercent >= 90);

    // Scenario C: Config drift (0 downtime, standard maintenance)
    const configFindings: FindingInput[] = [
      {
        id: "vuln-cfg",
        configKey: "ssh_idle_timeout",
        assetId: "ast-srv-app",
        assetHostname: "app.corp",
        cvssScore: 4.0,
      },
    ];
    const cfgPlans = RootCauseGroupingEngine.groupFindingsAndSimulate(configFindings, tenantId);
    assert.equal(cfgPlans[0].simulationResults.projectedBlastRadius.estimatedDowntimeMinutes, 0);
    assert.equal(cfgPlans[0].maintenanceWindow, "standard_maintenance");
  });

  // =========================================================================
  // 3. Deterministic Verification Methods
  // =========================================================================
  await t.test("VerificationMethods: Accurately proves system states across all check types", async () => {
    // Process Table Check
    const procSpec: VerificationCheckSpec = {
      method: "process_table_check",
      target: "xmrig_miner",
      expectedState: { running: false },
    };
    const procSuccess = await VerificationMethods.checkProcessTable(procSpec, {
      runningProcesses: ["systemd", "dockerd", "nginx"],
    });
    assert.equal(procSuccess.success, true);
    assert.equal(procSuccess.actualState.running, false);

    const procFail = await VerificationMethods.checkProcessTable(procSpec, {
      runningProcesses: [{ pid: 9942, name: "/tmp/xmrig_miner" }],
    });
    assert.equal(procFail.success, false);
    assert.equal(procFail.actualState.running, true);

    // Package Version Check (Never accept exit 0 alone)
    const pkgSpec: VerificationCheckSpec = {
      method: "package_version_check",
      target: "openssl",
      expectedState: { version: "3.0.2" },
    };
    const pkgSuccess = await VerificationMethods.checkPackageOrCve(pkgSpec, {
      installedVersion: "3.0.2",
    });
    assert.equal(pkgSuccess.success, true);

    const pkgFail = await VerificationMethods.checkPackageOrCve(pkgSpec, {
      installedVersion: "1.1.1n",
    });
    assert.equal(pkgFail.success, false);

    // Service Health Check
    const svcSpec: VerificationCheckSpec = {
      method: "service_health_check",
      target: "nginx",
      expectedState: { status: "healthy" },
    };
    const svcSuccess = await VerificationMethods.checkServiceHealth(svcSpec, {
      services: { nginx: { status: "running" } },
    });
    assert.equal(svcSuccess.success, true);

    const svcFail = await VerificationMethods.checkServiceHealth(svcSpec, {
      services: { nginx: { status: "failed" } },
    });
    assert.equal(svcFail.success, false);

    // Config State Check
    const cfgSpec: VerificationCheckSpec = {
      method: "config_state_check",
      target: "PermitRootLogin",
      expectedState: { value: "no" },
    };
    const cfgSuccess = await VerificationMethods.checkConfigState(cfgSpec, {
      config: { PermitRootLogin: "no" },
    });
    assert.equal(cfgSuccess.success, true);

    const cfgFail = await VerificationMethods.checkConfigState(cfgSpec, {
      config: { PermitRootLogin: "yes" },
    });
    assert.equal(cfgFail.success, false);

    // Port Reachability Check
    const portSpec: VerificationCheckSpec = {
      method: "port_reachability_check",
      target: "4444",
      expectedState: { open: false },
    };
    const portSuccess = await VerificationMethods.checkPortReachability(portSpec, {
      listeningPorts: [80, 443],
    });
    assert.equal(portSuccess.success, true);

    const portFail = await VerificationMethods.checkPortReachability(portSpec, {
      listeningPorts: [80, 443, 4444],
    });
    assert.equal(portFail.success, false);
  });

  // =========================================================================
  // 4. VerificationEngine: Closed-Loop Proof Before Action & Rollback Trigger
  // =========================================================================
  await t.test("VerificationEngine: Passes when all checks succeed", async () => {
    const plan = VerificationEngine.createPlan({
      action: "package_upgrade",
      agentId: "agt-web-01",
      tenantId,
      commandId: "cmd-upgrade-01",
      target: "curl",
      checks: [
        {
          method: "package_version_check",
          target: "curl",
          expectedState: { version: "8.4.0" },
        },
      ],
    });

    const result = await VerificationEngine.verify(plan, {
      installedVersion: "8.4.0",
    });

    assert.equal(result.verified, true);
    assert.equal(result.status, "VERIFIED");
    assert.equal(result.rollbackActionRequired, false);
    assert.ok(result.verificationHash && result.verificationHash.length === 64);
  });

  await t.test("VerificationEngine: Fail-closed path triggers rollback and reopens finding", async () => {
    const plan = VerificationEngine.createPlan({
      action: "package_upgrade",
      agentId: "agt-db-01",
      tenantId,
      commandId: "cmd-upgrade-fail",
      findingId: "cve-2024-9999",
      snapshotId: "snap-preflight-001",
      target: "libpq",
      checks: [
        {
          method: "package_version_check",
          target: "libpq",
          expectedState: { version: "15.4" },
        },
      ],
    });

    // Endpoint evidence shows package was NOT updated (failed post-state proof)
    const hostEvidence = {
      installedVersion: "14.1", // Outdated!
    };

    const result = await VerificationEngine.verify(plan, hostEvidence);

    assert.equal(result.verified, false);
    assert.equal(result.status, "FAILED");
    assert.equal(result.rollbackActionRequired, true);
    assert.equal(result.rollbackExecuted, true);
    assert.equal(result.findingReopened, true);
    assert.ok(result.failureReason?.includes("Verification failed"));
    assert.ok(result.rollbackResult);
  });

  // =========================================================================
  // 5. Continuous Recheck & Drift Detection
  // =========================================================================
  await t.test("ContinuousRecheckService: Registers and detects post-closure drift", async () => {
    const schedule = await ContinuousRecheckService.registerSchedule({
      tenantId,
      findingId: "CVE-2023-38545",
      assetId: "ast-srv-proxy",
      action: "package_upgrade curl",
      checkSpec: {
        method: "package_version_check",
        target: "curl",
        expectedState: { version: "8.4.0" },
      },
      frequencyHours: 12,
    });

    assert.ok(schedule.id.startsWith("cr-"));
    assert.equal(schedule.status, "active");
    assert.equal(schedule.consecutivePasses, 0);

    // Audit 1: Clean state -> check passes
    const passResult = await ContinuousRecheckService.auditSchedule(schedule, {
      installedVersion: "8.4.0",
    });
    assert.equal(passResult.driftDetected, false);
    assert.equal(passResult.reopened, false);
    assert.equal(schedule.consecutivePasses, 1);

    // Audit 2: Configuration/package drift! (e.g., administrator downgraded or reverted snapshot)
    const driftResult = await ContinuousRecheckService.auditSchedule(schedule, {
      installedVersion: "7.88.1", // Regressed!
    });
    assert.equal(driftResult.driftDetected, true);
    assert.equal(driftResult.reopened, true);
    assert.equal(schedule.status, "drift_detected");
    assert.ok(driftResult.checkResult.details.includes("Verification failed"));
  });
});
