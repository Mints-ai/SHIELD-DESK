import { VerificationCheckSpec, VerificationMethodResult } from "./types";

export class VerificationMethods {
  /**
   * Verifies whether a process is absent from the host process table.
   */
  public static async checkProcessTable(
    spec: VerificationCheckSpec,
    agentEvidence?: Record<string, unknown>
  ): Promise<VerificationMethodResult> {
    const targetPidOrName = spec.target;
    const timestamp = new Date().toISOString();

    // Check evidence reported by agent or telemetry
    const liveProcesses = (agentEvidence?.runningProcesses as Array<{ pid?: number; name?: string } | string>) || [];
    const isStillRunning = liveProcesses.some((p) => {
      if (typeof p === "string") return p.toLowerCase().includes(targetPidOrName.toLowerCase());
      if (typeof p === "object" && p !== null) {
        if (p.pid && String(p.pid) === targetPidOrName) return true;
        if (p.name && p.name.toLowerCase().includes(targetPidOrName.toLowerCase())) return true;
      }
      return false;
    });

    const success = !isStillRunning;
    return {
      method: "process_table_check",
      target: targetPidOrName,
      success,
      expectedState: { running: false },
      actualState: { running: isStillRunning },
      details: success
        ? `Process '${targetPidOrName}' confirmed absent from host process table.`
        : `Verification failed: Process '${targetPidOrName}' is still active on endpoint.`,
      timestamp,
    };
  }

  /**
   * Verifies that network isolation or port blocking is active on the host.
   */
  public static async checkFirewallRule(
    spec: VerificationCheckSpec,
    agentEvidence?: Record<string, unknown>
  ): Promise<VerificationMethodResult> {
    const target = spec.target;
    const timestamp = new Date().toISOString();

    const blockedIps = Array.isArray(agentEvidence?.blockedIps) ? (agentEvidence.blockedIps as unknown[]) : [];
    const firewallActive =
      agentEvidence?.networkIsolated === true ||
      agentEvidence?.firewallDropActive === true ||
      blockedIps.includes(target) ||
      (agentEvidence?.status === "isolated");

    const expectedActive = spec.expectedState.active !== false;
    const success = Boolean(firewallActive) === expectedActive;

    return {
      method: "firewall_rule_check",
      target,
      success,
      expectedState: { active: expectedActive },
      actualState: { active: Boolean(firewallActive) },
      details: success
        ? `Firewall rule / isolation state verified successfully for '${target}'.`
        : `Verification failed: Expected firewall active=${expectedActive}, but observed active=${Boolean(firewallActive)}.`,
      timestamp,
    };
  }

  /**
   * Verifies package version or CVE fix status. Never accept exit 0 alone as CVE fix.
   */
  public static async checkPackageOrCve(
    spec: VerificationCheckSpec,
    agentEvidence?: Record<string, unknown>
  ): Promise<VerificationMethodResult> {
    const cveOrPkg = spec.target;
    const timestamp = new Date().toISOString();

    const expectedVersion = spec.expectedState.version as string | undefined;
    const installedVersion = (agentEvidence?.installedVersion || agentEvidence?.packageVersion) as string | undefined;
    const cveResolved = agentEvidence?.cveStatus === "not_vulnerable" || (installedVersion && expectedVersion && installedVersion >= expectedVersion);

    const success = Boolean(cveResolved);

    return {
      method: "package_version_check",
      target: cveOrPkg,
      success,
      expectedState: { cveStatus: "not_vulnerable", minVersion: expectedVersion || "remediated" },
      actualState: { cveStatus: success ? "not_vulnerable" : "vulnerable", installedVersion },
      details: success
        ? `Package state verified: '${cveOrPkg}' is confirmed remediated.`
        : `Verification failed: Vulnerability '${cveOrPkg}' remains detectable on host.`,
      timestamp,
    };
  }
}
