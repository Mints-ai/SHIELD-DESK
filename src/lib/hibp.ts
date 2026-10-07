import fs from "fs";
import path from "path";

export interface HibpStatus {
  configured: boolean;
  message?: string;
}

export function getHibpApiKey(): string | undefined {
  if (process.env.HIBP_API_KEY && process.env.HIBP_API_KEY.trim() !== "") {
    return process.env.HIBP_API_KEY.trim();
  }

  try {
    const root = process.cwd();
    const envPaths = [path.join(root, ".env.local"), path.join(root, ".env")];
    for (const p of envPaths) {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, "utf-8");
        for (const line of content.split("\n")) {
          const trimmed = line.trim();
          if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;
          const [key, ...vals] = trimmed.split("=");
          if (key.trim() === "HIBP_API_KEY") {
            const val = vals.join("=").trim().replace(/^["']|["']$/g, "");
            if (val) {
              process.env.HIBP_API_KEY = val;
              return val;
            }
          }
        }
      }
    }
  } catch {
    // Ignore FS error
  }
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
