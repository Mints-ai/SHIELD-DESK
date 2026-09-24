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
process.env.SHIELDDESK_SESSION_SECRET =
  process.env.SHIELDDESK_SESSION_SECRET || "test-session-secret-for-unit-testing-minimum-32-chars!";
process.env.SHIELDDESK_INGEST_API_KEY =
  process.env.SHIELDDESK_INGEST_API_KEY || "test-ingest-api-key-12345";
process.env.SHIELDDESK_INGEST_API_KEYS = JSON.stringify({
  "test-acme-ingest-key": "acme-tenant",
  "test-globex-ingest-key": "globex-tenant",
});
