import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { PerformanceLoadTester } from "./perf/load-test";

test("Phase 32: Multi-Tenant Performance & Throughput Benchmark Suite", async (t) => {
  await t.test("Benchmark: Executes multi-tenant telemetry and decision processing measuring p50/p95/p99", async () => {
    const report = await PerformanceLoadTester.runBenchmark({
      tenantCount: 5,
      eventsPerTenant: 50,
    });

    assert.equal(report.totalEventsProcessed, 250);
    assert.ok(report.throughputEventsPerSec > 100, "Throughput must exceed 100 ops/sec");
    assert.ok(report.latenciesMs.p50 < 10, "p50 latency must be sub-10ms");
    assert.ok(report.latenciesMs.p99 < 50, "p99 latency must be sub-50ms");
    assert.equal(report.errorRate, 0, "Error rate must be 0%");
  });
});
