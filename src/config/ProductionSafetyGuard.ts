import { getConfig } from "./index";

export class SecuritySafetyViolationError extends Error {
  public readonly action: string;
  public readonly environment: string;
  public readonly timestamp: string;

  constructor(action: string, reason: string) {
    const env = getConfig().environment;
    super(`[ProductionSafetyGuard] Violation in environment '${env}': Action '${action}' is prohibited. Reason: ${reason}`);
    this.name = "SecuritySafetyViolationError";
    this.action = action;
    this.environment = env;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * ProductionSafetyGuard
 *
 * Deterministic runtime gatekeeper preventing simulated data, demo personas,
 * fake scans, and mock credentials from ever executing in production.
 */
export class ProductionSafetyGuard {
  /**
   * Asserts whether a given action is allowed under the current runtime environment.
   * Throws SecuritySafetyViolationError if the action attempts demo or simulation behavior in production.
   */
  public static assertProductionSafe(actionName: string, context?: Record<string, unknown>): void {
    const config = getConfig();

    if (config.isProduction) {
      if (actionName.startsWith("demo_") || actionName.startsWith("mock_") || actionName.startsWith("sim_")) {
        throw new SecuritySafetyViolationError(
          actionName,
          `Prefix '${actionName.split("_")[0]}_' denotes non-production behavior forbidden in production.`
        );
      }
    }
  }

  /**
   * Guards against fake / mock vulnerability scans in production.
   */
  public static guardFakeScan(scanType: string): void {
    const config = getConfig();
    if (config.isProduction || !config.demoMode) {
      throw new SecuritySafetyViolationError(
        `scan:${scanType}:fallback`,
        "Synthetic scan results and simulated CVE detections are forbidden in production. Must fail closed."
      );
    }
  }

  /**
   * Guards against simulated agent command execution.
   */
  public static guardSimulatedCommand(command: string): void {
    const config = getConfig();
    if (config.isProduction || !config.simulationAllowed) {
      throw new SecuritySafetyViolationError(
        `command:${command}:simulation`,
        "Simulated command dispatch is disabled in production. Real agent connection is required."
      );
    }
  }

  /**
   * Guards against fake patch results. Never claim PATCH_SUCCESS without verification.
   */
  public static guardFakePatch(cveId: string): void {
    const config = getConfig();
    if (config.isProduction || !config.demoMode) {
      throw new SecuritySafetyViolationError(
        `patch:${cveId}:simulated_success`,
        "Simulated patch success is strictly prohibited in production. Live host state verification required."
      );
    }
  }

  /**
   * Guards against fake billing / mock subscription generation.
   */
  public static guardFakeBilling(tenantId: string): void {
    const config = getConfig();
    if (config.isProduction) {
      throw new SecuritySafetyViolationError(
        `billing:${tenantId}:mock_upgrade`,
        "Direct simulated plan upgrades are forbidden in production. Verified Stripe webhook settlement required."
      );
    }
  }

  /**
   * Guards against fake license key generation or offline bypass.
   */
  public static guardFakeLicense(licenseKey: string): void {
    const config = getConfig();
    if (config.isProduction) {
      throw new SecuritySafetyViolationError(
        `license:${licenseKey}:bypass`,
        "Offline license bypass is strictly forbidden in production."
      );
    }
  }

  /**
   * Guards against developer persona switching (dev-admin, dev-analyst) in production.
   */
  public static guardDevPersona(personaId: string): void {
    const config = getConfig();
    if (config.isProduction || !config.devPersonasAllowed) {
      throw new SecuritySafetyViolationError(
        `auth:persona:${personaId}`,
        "Quick persona authentication is strictly prohibited in production and staging."
      );
    }
  }

  public static isDemoAllowed(): boolean {
    return getConfig().demoMode;
  }

  public static isSimulationAllowed(): boolean {
    return getConfig().simulationAllowed;
  }

  public static isDevPersonaAllowed(): boolean {
    return getConfig().devPersonasAllowed;
  }
}
