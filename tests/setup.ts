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
