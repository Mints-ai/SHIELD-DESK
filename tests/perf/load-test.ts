import { TelemetryPipeline } from "../../src/lib/telemetry/pipeline";
import { ConnectorRegistry } from "../../src/lib/connectors/registry";
import { DecisionEngine } from "../../src/lib/decision-engine/engine";
import { SecurityDigitalTwin } from "../../src/lib/security-twin/digitalTwin";

export interface PerfBenchmarkReport {
  testSuite: string;
  totalEventsProcessed: number;
  durationMs: number;
  throughputEventsPerSec: number;
  latenciesMs: {
    p50: number;
    p95: number;
    p99: number;
    max: number;
  };
  errorRate: number;
  memoryUsageMb: number;
}

export class PerformanceLoadTester {
  /**
   * Simulates high-throughput multi-tenant event ingestion and decision evaluation
   * measuring real p50, p95, and p99 latencies without synthetic fabrication.
   */
  public static async runBenchmark(options: {
    tenantCount?: number;
    eventsPerTenant?: number;
  } = {}): Promise<PerfBenchmarkReport> {
    const tenantCount = options.tenantCount || 10;
    const eventsPerTenant = options.eventsPerTenant || 100;
    const totalEvents = tenantCount * eventsPerTenant;

    const latencies: number[] = [];
    let errorCount = 0;
    const overallStart = Date.now();

    for (let t = 0; t < tenantCount; t++) {
      const tenantId = `perf-tenant-${t}`;

      for (let e = 0; e < eventsPerTenant; e++) {
        const itemStart = performance.now();
        try {
          // Ingest telemetry
          await TelemetryPipeline.processBatch(
            [
              {
                timestamp: new Date().toISOString(),
                hostname: `host-${e % 20}`,
                EventID: 1,
                CommandLine: `process-worker-${e}.exe --batch`,
              },
            ],
            { tenantId, agentId: `agent-${e % 20}` }
          );

          // Evaluate decision gateway
          await DecisionEngine.evaluate({
            tenantId,
            action: "inspect_process",
            assetId: `agent-${e % 20}`,
            evidence: [],
            actor: { id: "perf-analyst", role: "analyst", tenantId },
          });

          latencies.push(performance.now() - itemStart);
        } catch {
          errorCount++;
          latencies.push(performance.now() - itemStart);
        }
      }
    }

    const durationMs = Date.now() - overallStart;
    latencies.sort((a, b) => a - b);

    const p50 = latencies[Math.floor(latencies.length * 0.5)] || 0;
    const p95 = latencies[Math.floor(latencies.length * 0.95)] || 0;
    const p99 = latencies[Math.floor(latencies.length * 0.99)] || 0;
    const max = latencies[latencies.length - 1] || 0;

    const mem = process.memoryUsage().heapUsed / 1024 / 1024;

    return {
      testSuite: `Multi-Tenant Load Benchmark (${tenantCount} tenants, ${totalEvents} operations)`,
      totalEventsProcessed: totalEvents,
      durationMs,
      throughputEventsPerSec: Math.round((totalEvents / (durationMs / 1000))),
      latenciesMs: {
        p50: Number(p50.toFixed(2)),
        p95: Number(p95.toFixed(2)),
        p99: Number(p99.toFixed(2)),
        max: Number(max.toFixed(2)),
      },
      errorRate: Number((errorCount / totalEvents).toFixed(4)),
      memoryUsageMb: Number(mem.toFixed(2)),
    };
  }
}
