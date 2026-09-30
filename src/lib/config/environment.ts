/**
 * ShieldDesk Environment & Runtime Safety Boundaries
 *
 * Centralizes environment detection, demo simulation gating, and
 * fail-closed policies across all control-plane APIs and services.
 * Bridged with strict schema validation in @/config.
 */

import {
  getConfig,
  AppEnvironment,
  ProductionSafetyGuard,
  SecuritySafetyViolationError,
} from "@/config";

export type { AppEnvironment };

/**
 * Returns the current application deployment environment.
 */
export function getAppEnvironment(): AppEnvironment {
  return getConfig().environment;
}

/**
 * True if running under a production deployment.
 */
export function isProduction(): boolean {
  return getConfig().isProduction;
}

/**
 * True if demo/simulation fixtures and fallback data are permitted.
 * Strictly forbidden in production environments under any circumstances.
 */
export function isDemoMode(): boolean {
  return getConfig().demoMode;
}

export const isDemoModeActive = isDemoMode;

/**
 * True if the application must fail closed when dependencies are unreachable,
 * rather than returning simulated results.
 * ALWAYS true in production.
 */
export function shouldFailClosed(): boolean {
  return getConfig().failClosed;
}

/**
 * Controls whether endpoint command simulation is permitted.
 */
export function isSimulationAllowed(): boolean {
  return getConfig().simulationAllowed;
}

/**
 * True if development persona switching (dev-admin, dev-analyst, dev-other)
 * is permitted for testing. Strictly forbidden in production.
 */
export function isDevPersonaAllowed(): boolean {
  return getConfig().devPersonasAllowed;
}

/**
 * Environment metadata payload safe for consumption by frontend status indicators.
 */
export function getClientEnvironmentMetadata() {
  const cfg = getConfig();
  return {
    environment: cfg.environment,
    isProduction: cfg.isProduction,
    isDemoMode: cfg.demoMode,
    failClosed: cfg.failClosed,
    devPersonasAllowed: cfg.devPersonasAllowed,
    simulationAllowed: cfg.simulationAllowed,
  };
}

export { ProductionSafetyGuard, SecuritySafetyViolationError };
