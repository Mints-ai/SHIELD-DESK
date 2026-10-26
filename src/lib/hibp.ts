import fs from "fs";
import path from "path";

export interface HibpStatus {
  configured: boolean;
  message?: string;
}

/**
 * Retrieves the HaveIBeenPwned API key from disk (.env.local / .env) or process.env.
 * Prioritizes active disk state (.env.local) so updates and removals take effect immediately.
 */
export function getHibpApiKey(): string | undefined {
  // 1. Scan local .env.local on disk first so active UI edits and deletions take effect immediately
  try {
    const root = process.cwd();
    const envLocalPath = path.join(root, ".env.local");
    if (fs.existsSync(envLocalPath)) {
      const content = fs.readFileSync(envLocalPath, "utf-8");
      let foundInLocal = false;
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;
        const [key, ...vals] = trimmed.split("=");
        if (key.trim() === "HIBP_API_KEY") {
          foundInLocal = true;
          const val = vals.join("=").trim().replace(/^["']|["']$/g, "");
          if (val && val.length > 0) {
            process.env.HIBP_API_KEY = val;
            return val;
          }
          // Explicitly blank in .env.local
          delete process.env.HIBP_API_KEY;
          return undefined;
        }
      }
      // If .env.local exists but HIBP_API_KEY is not defined in it, the key is removed
      if (!foundInLocal) {
        delete process.env.HIBP_API_KEY;
        return undefined;
      }
    }
  } catch {
    // Ignore FS error
  }

  // 2. Fall back to process.env if .env.local does not exist (e.g. production / container environments)
  const envVal = process.env.HIBP_API_KEY?.trim();
  if (envVal && envVal.length > 0) {
    return envVal;
  }

  // 3. Fall back to root .env if present
  try {
    const root = process.cwd();
    const envPath = path.join(root, ".env");
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;
        const [key, ...vals] = trimmed.split("=");
        if (key.trim() === "HIBP_API_KEY") {
          const val = vals.join("=").trim().replace(/^["']|["']$/g, "");
          if (val && val.length > 0) {
            process.env.HIBP_API_KEY = val;
            return val;
          }
        }
      }
    }
  } catch {
    // Ignore FS error
  }

  delete process.env.HIBP_API_KEY;
  return undefined;
}

export function getHibpStatus(): HibpStatus {
  const key = getHibpApiKey();
  if (!key) {
    return {
      configured: false,
      message: "HIBP_API_KEY not configured in environment.",
    };
  }
  return {
    configured: true,
    message: "HIBP API key configured and ready for domain breach monitoring.",
  };
}
