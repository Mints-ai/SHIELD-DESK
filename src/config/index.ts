import { ShieldDeskConfig, validateEnvironment } from "./schema";

let cachedConfig: ShieldDeskConfig | null = null;

/**
 * Returns the validated configuration singleton.
 * In production/staging, results are cached. In test mode, process.env is evaluated dynamically.
 */
export function getConfig(): ShieldDeskConfig {
  if (process.env.NODE_ENV === "test" || !cachedConfig) {
    return validateEnvironment(process.env);
  }
  return cachedConfig;
}

/**
 * Explicitly forces re-evaluation of process.env (useful during testing and runtime updates).
 */
export function reloadConfig(overrideEnv?: Record<string, string | undefined>): ShieldDeskConfig {
  cachedConfig = validateEnvironment(overrideEnv || process.env);
  return cachedConfig;
}

/**
 * Resets the cached configuration to null.
 */
export function resetConfig(): void {
  cachedConfig = null;
}

export * from "./schema";
export * from "./ProductionSafetyGuard";
