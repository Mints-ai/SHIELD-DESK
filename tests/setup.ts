/**
 * Test setup environment for ShieldDesk test suites.
 * Shims 'server-only' so Node's native test runner can execute tests
 * against server modules cleanly.
 */
import Module from "node:module";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const originalRequire = (Module.prototype as any).require;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(Module.prototype as any).require = function (id: string) {
  if (id === "server-only") {
    return {};
  }
  return originalRequire.apply(this, arguments);
};

// Set test secrets for cryptographically verified testing
(process.env as Record<string, string | undefined>).NODE_ENV = process.env.NODE_ENV || "test";
process.env.RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || "rzp_webhook_secret";
process.env.STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "whsec_test_secret";
process.env.DATABASE_URL = "";
process.env.NEXT_PUBLIC_SUPABASE_URL = "";
process.env.SUPABASE_SERVICE_ROLE_KEY = "";
process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "";
process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = "";
process.env.SHIELDDESK_SESSION_SECRET =
  process.env.SHIELDDESK_SESSION_SECRET || "test-session-secret-for-unit-testing-minimum-32-chars!";
process.env.SHIELDDESK_INGEST_API_KEY =
  process.env.SHIELDDESK_INGEST_API_KEY || "test-ingest-api-key-12345";
process.env.SHIELDDESK_INGEST_API_KEYS = JSON.stringify({
  "test-acme-ingest-key": "acme-tenant",
  "test-globex-ingest-key": "globex-tenant",
});
process.env.SCAN_SERVICE_URL = "http://127.0.0.1:59999";
process.env.PYTHON_AI_SERVICE_URL = "http://127.0.0.1:59999";
process.env.AI_ADVISOR_URL = "http://127.0.0.1:59999";
process.env.SENTRY_DSN = "";
process.env.NEXT_PUBLIC_SENTRY_DSN = "";
process.env.DISCORD_WEBHOOK_URL = "";
process.env.SLACK_WEBHOOK_URL = "";
process.env.TEAMS_WEBHOOK_URL = "";
process.env.SECURITY_WEBHOOK_URL = "";

// Clean up background DB pools or open handles so test runner exits promptly
process.on("beforeExit", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if ((global as any).__shieldDeskPgPool) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (global as any).__shieldDeskPgPool.end().catch(() => {});
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (global as any).__shieldDeskPgPool = undefined;
  }
});
