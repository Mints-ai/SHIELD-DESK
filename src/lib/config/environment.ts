/**
 * ShieldDesk Environment & Runtime Safety Boundaries
 *
 * Centralizes environment detection, demo simulation gating, and
 * fail-closed policies across all control-plane APIs and services.
 *
 * Directives:
 * - DEMO_MODE: When true, enables fallback fixtures for local development,
 *   demos, and evaluation. Defaults to true in non-production, false in production.
 * - FAIL_CLOSED: In production (or when DEMO_MODE=false), any offline or
 *   unavailable dependency (scanners, agent daemons, telemetry lakes)
 *   MUST fail closed with an explicit error rather than silently returning
 *   simulated success.
 * - DEV_PERSONAS: Mock user switching (dev-admin, dev-analyst, etc.) is strictly
 *   prohibited in production environments.
 */

export type AppEnvironment = "development" | "staging" | "production" | "test";

/**
 * Returns the current application deployment environment.
 */
export function getAppEnvironment(): AppEnvironment {
  const env = process.env.APP_ENV || process.env.NODE_ENV || "development";
  if (env === "production") return "production";
  if (env === "staging") return "staging";
  if (env === "test") return "test";
  return "development";
}

/**
 * True if running under a production deployment.
 */
export function isProduction(): boolean {
  return getAppEnvironment() === "production";
}

/**
 * True if demo/simulation fixtures and fallback data are permitted.
 * Defaults to true in development/test, false in production.
 * Can be explicitly overridden via process.env.DEMO_MODE ("true" | "false").
 */
export function isDemoMode(): boolean {
  if (process.env.DEMO_MODE === "true") return true;
  if (process.env.DEMO_MODE === "false") return false;
  return !isProduction();
}

/**
 * True if the application must fail closed when dependencies are unreachable,
 * rather than returning simulated results.
 */
export function shouldFailClosed(): boolean {
  return isProduction() && !isDemoMode();
}

/**
 * True if development persona switching (dev-admin, dev-analyst, dev-other)
 * is permitted for testing. Strictly forbidden in production.
 */
export function isDevPersonaAllowed(): boolean {
  return !isProduction() && isDemoMode();
}

/**
 * Environment metadata payload safe for consumption by frontend status indicators.
 */
export function getClientEnvironmentMetadata() {
  return {
    environment: getAppEnvironment(),
    isProduction: isProduction(),
    isDemoMode: isDemoMode(),
    failClosed: shouldFailClosed(),
    devPersonasAllowed: isDevPersonaAllowed(),
  };
}
