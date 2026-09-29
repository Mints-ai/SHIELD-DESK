import * as Sentry from "@sentry/nextjs";
import * as fs from "fs";
import * as path from "path";

// 1. Manually parse .env.local to guarantee DSN is present
const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith("#") && trimmed.includes("=")) {
      const [key, ...values] = trimmed.split("=");
      const val = values.join("=").trim();
      process.env[key.trim()] = val;
    }
  }
}

const dsn = process.env.SENTRY_DSN || process.env.NEXT_PUBLIC_SENTRY_DSN;
console.log("Using Sentry DSN:", dsn ? dsn.replace(/:[^@]+@/, ":***@") : "NONE");

if (!dsn) {
  console.error("ERROR: No Sentry DSN found in environment or .env.local!");
  process.exit(1);
}

// 2. Initialize Sentry
Sentry.init({
  dsn,
  tracesSampleRate: 1.0,
  environment: "development",
  debug: true,
});

async function main() {
  console.log("Triggering sample error to verify Sentry connection...");
  
  const eventId = Sentry.captureException(
    new Error("ShieldDesk™ — Verification Test Event: Sentry Integration Active!"),
    {
      tags: {
        platform: "shielddesk-soc",
        component: "production-readiness-audit",
        tenant: "acme-tenant",
      },
      extra: {
        verifiedAt: new Date().toISOString(),
        auditor: "antigravity-soc-agent",
        readinessStatus: "PASSED_81_TESTS",
      },
    }
  );

  console.log("Event captured with ID:", eventId);
  console.log("Flushing event to Sentry server...");
  
  const flushed = await Sentry.flush(5000);
  console.log("Flush complete:", flushed ? "SUCCESS (event transmitted)" : "TIMEOUT");
}

main().catch(console.error);
