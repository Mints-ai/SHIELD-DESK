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

    const liveProcesses = (agentEvidence?.runningProcesses as Array<{ pid?: number; name?: string } | string>) || [];
    const isStillRunning = liveProcesses.some((p) => {
      if (typeof p === "string") return p.toLowerCase().includes(targetPidOrName.toLowerCase());
      if (typeof p === "object" && p !== null) {
        if (p.pid && String(p.pid) === targetPidOrName) return true;
        if (p.name && p.name.toLowerCase().includes(targetPidOrName.toLowerCase())) return true;
      }
      return false;
    });

    const expectedRunning = spec.expectedState.running === true;
    const success = isStillRunning === expectedRunning;

    return {
      method: "process_table_check",
      target: targetPidOrName,
      success,
      expectedState: { running: expectedRunning },
      actualState: { running: isStillRunning },
      details: success
        ? expectedRunning
          ? `Process '${targetPidOrName}' confirmed active in process table.`
          : `Process '${targetPidOrName}' confirmed absent from host process table.`
        : expectedRunning
          ? `Verification failed: Process '${targetPidOrName}' is not running.`
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
      agentEvidence?.status === "isolated";

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

    let cveResolved = false;
    if (agentEvidence?.cveStatus === "not_vulnerable" || agentEvidence?.cveStatus === "remediated") {
      cveResolved = true;
    } else if (installedVersion && expectedVersion) {
      cveResolved = installedVersion >= expectedVersion;
    } else if (Array.isArray(agentEvidence?.resolvedCves) && agentEvidence.resolvedCves.includes(cveOrPkg)) {
      cveResolved = true;
    } else if (agentEvidence?.remediated === true) {
      cveResolved = true;
    }

    const success = Boolean(cveResolved);

    return {
      method: spec.method === "vulnerability_rescan" ? "vulnerability_rescan" : "package_version_check",
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

  /**
   * Verifies service health (e.g., systemd unit active, container healthy, HTTP probe).
   */
  public static async checkServiceHealth(
    spec: VerificationCheckSpec,
    agentEvidence?: Record<string, unknown>
  ): Promise<VerificationMethodResult> {
    const serviceName = spec.target;
    const timestamp = new Date().toISOString();

    const services = (agentEvidence?.services as Record<string, { status?: string; active?: boolean } | string>) || {};
    const serviceEntry = services[serviceName];

    let isHealthy = false;
    let observedStatus = "unknown";

    if (typeof serviceEntry === "string") {
      observedStatus = serviceEntry.toLowerCase();
      isHealthy = observedStatus === "active" || observedStatus === "running" || observedStatus === "healthy";
    } else if (typeof serviceEntry === "object" && serviceEntry !== null) {
      observedStatus = (serviceEntry.status || (serviceEntry.active ? "active" : "inactive")).toLowerCase();
      isHealthy = observedStatus === "active" || observedStatus === "running" || observedStatus === "healthy" || serviceEntry.active === true;
    } else if (agentEvidence?.serviceHealth === "healthy" || agentEvidence?.status === "healthy" || agentEvidence?.serviceActive === true) {
      isHealthy = true;
      observedStatus = "healthy";
    }

    const expectedHealthy = spec.expectedState.status !== "inactive" && spec.expectedState.status !== "failed";
    const success = isHealthy === expectedHealthy;

    return {
      method: "service_health_check",
      target: serviceName,
      success,
      expectedState: { status: expectedHealthy ? "healthy" : "inactive" },
      actualState: { status: observedStatus },
      details: success
        ? `Service health verified for '${serviceName}': status is ${observedStatus}.`
        : `Verification failed: Service '${serviceName}' status is '${observedStatus}', expected healthy=${expectedHealthy}.`,
      timestamp,
    };
  }

  /**
   * Verifies system or application configuration parameter state.
   */
  public static async checkConfigState(
    spec: VerificationCheckSpec,
    agentEvidence?: Record<string, unknown>
  ): Promise<VerificationMethodResult> {
    const configKey = spec.target;
    const timestamp = new Date().toISOString();

    const configData = (agentEvidence?.config || agentEvidence?.systemConfig || agentEvidence?.settings) as Record<string, unknown> | undefined;
    const observedValue = configData ? configData[configKey] : agentEvidence?.[configKey];

    const expectedValue = spec.expectedState.value !== undefined ? spec.expectedState.value : spec.expectedState.expected;
    const success = observedValue !== undefined && JSON.stringify(observedValue) === JSON.stringify(expectedValue);

    return {
      method: "config_state_check",
      target: configKey,
      success,
      expectedState: { value: expectedValue },
      actualState: { value: observedValue },
      details: success
        ? `Configuration parameter '${configKey}' verified: set to ${JSON.stringify(observedValue)}.`
        : `Verification failed: Config '${configKey}' is ${JSON.stringify(observedValue)}, expected ${JSON.stringify(expectedValue)}.`,
      timestamp,
    };
  }

  /**
   * Verifies port reachability (e.g., confirming a blocked port is closed or service port is listening).
   */
  public static async checkPortReachability(
    spec: VerificationCheckSpec,
    agentEvidence?: Record<string, unknown>
  ): Promise<VerificationMethodResult> {
    const portTarget = spec.target;
    const timestamp = new Date().toISOString();

    const listeningPorts = (agentEvidence?.listeningPorts || agentEvidence?.openPorts) as Array<number | string> | undefined;
    const portNum = parseInt(portTarget.split(":").pop() || portTarget, 10);

    const isListening = Array.isArray(listeningPorts) && listeningPorts.some((p) => Number(p) === portNum);
    const expectedOpen = spec.expectedState.open === true || spec.expectedState.reachable === true;
    const success = isListening === expectedOpen;

    return {
      method: "port_reachability_check",
      target: portTarget,
      success,
      expectedState: { open: expectedOpen },
      actualState: { open: isListening },
      details: success
        ? `Port reachability verified for '${portTarget}': open=${isListening}.`
        : `Verification failed: Port '${portTarget}' open=${isListening}, expected open=${expectedOpen}.`,
      timestamp,
    };
  }
}
