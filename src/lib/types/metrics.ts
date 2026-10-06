/**
 * ShieldDesk Metric Status and Customer Presentation Model
 *
 * Implements strict data transparency rules:
 * - MEASURED: Direct real-time or aggregated telemetry from this tenant's environment.
 * - ESTIMATED: Derived from local feature coverage or heuristic baseline.
 * - BENCHMARK: Industry reference figure (e.g. IBM Cost of a Data Breach Report, SANS MTTD).
 * - UNAVAILABLE: Metric cannot be calculated due to lack of connected data sources.
 */

export type MetricStatus = "MEASURED" | "ESTIMATED" | "BENCHMARK" | "UNAVAILABLE";

export interface MetricValue<T = number | string> {
  value: T;
  status: MetricStatus;
  source: string;
  timestamp: string;
  methodology?: string;
}

export function createMetric<T = number | string>(
  value: T,
  status: MetricStatus,
  source: string,
  methodology?: string
): MetricValue<T> {
  return {
    value,
    status,
    source,
    timestamp: new Date().toISOString(),
    methodology,
  };
}
