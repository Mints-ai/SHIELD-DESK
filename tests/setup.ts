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
process.env.SHIELDDESK_INGEST_TENANT =
  process.env.SHIELDDESK_INGEST_TENANT || "acme-tenant";
process.env.SHIELDDESK_INGEST_API_KEYS = JSON.stringify({
  "test-acme-ingest-key": "acme-tenant",
  "test-globex-ingest-key": "globex-tenant",
  "test-mints-ingest-key": "mints-global",
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

// Initialize test fixtures strictly within unit test runner process
const { MOCK_ENDPOINT_AGENTS } = require("../src/lib/fleet/fleet");
if (MOCK_ENDPOINT_AGENTS && MOCK_ENDPOINT_AGENTS.length === 0) {
  MOCK_ENDPOINT_AGENTS.push(
    {
      id: "ea111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      hostname: "FIN-WS-042",
      ip_address: "10.0.4.42",
      os_type: "windows",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 42.5,
      memory_usage: 68.2,
      eps: 145,
      kill_switch_active: false,
      safety_snapshot_id: "snap-finws042-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
    },
    {
      id: "ea222222-2222-2222-2222-222222222222",
      tenant_id: "acme-tenant",
      hostname: "FIN-DB-01",
      ip_address: "10.0.4.10",
      os_type: "linux",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 18.2,
      memory_usage: 84.1,
      eps: 412,
      kill_switch_active: false,
      safety_snapshot_id: "snap-findb01-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
    },
    {
      id: "ea333333-3333-3333-3333-333333333333",
      tenant_id: "acme-tenant",
      hostname: "ENG-LAPTOP-09",
      ip_address: "10.0.12.9",
      os_type: "linux",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 12.1,
      memory_usage: 45.0,
      eps: 32,
      kill_switch_active: false,
      safety_snapshot_id: "snap-eng09-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    },
    {
      id: "ea444444-4444-4444-4444-444444444444",
      tenant_id: "acme-tenant",
      hostname: "PROD-API-01",
      ip_address: "10.0.2.100",
      os_type: "linux",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 64.8,
      memory_usage: 71.3,
      eps: 890,
      kill_switch_active: false,
      safety_snapshot_id: "snap-prodapi-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    },
    {
      id: "ea555555-5555-5555-5555-555555555555",
      tenant_id: "globex-tenant",
      hostname: "GLX-SEC-01",
      ip_address: "192.168.1.15",
      os_type: "linux",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 15.0,
      memory_usage: 38.0,
      eps: 80,
      kill_switch_active: false,
      safety_snapshot_id: "snap-glx01-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
    }
  );
}

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
