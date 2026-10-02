export interface MetricCounter {
  name: string;
  help: string;
  labels: Record<string, string>;
  value: number;
}

export interface MetricHistogram {
  name: string;
  help: string;
  buckets: number[];
  counts: number[];
  sum: number;
  count: number;
}

export class MetricsRegistry {
  private static counters: Map<string, number> = new Map();
  private static histograms: Map<string, number[]> = new Map();
  private static readonly latencyBucketsMs = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

  public static increment(name: string, value = 1, labels: Record<string, string> = {}): void {
    const key = this.serializeKey(name, labels);
    const curr = this.counters.get(key) || 0;
    this.counters.set(key, curr + value);
  }

  public static observe(name: string, value: number, labels: Record<string, string> = {}): void {
    if (!Number.isFinite(value) || value < 0) return;
    const key = this.serializeKey(name, labels);
    if (!this.histograms.has(key)) {
      this.histograms.set(key, []);
    }
    this.histograms.get(key)!.push(value);
  }

  public static getCounter(name: string, labels: Record<string, string> = {}): number {
    const key = this.serializeKey(name, labels);
    return this.counters.get(key) || 0;
  }

  /**
   * Generates Prometheus exposition format output.
   */
  public static toPrometheus(): string {
    const lines: string[] = [];

    // System banner
    lines.push("# HELP shielddesk_build_info ShieldDesk build and version information.");
    lines.push("# TYPE shielddesk_build_info gauge");
    lines.push('shielddesk_build_info{version="2.4.0",platform="enterprise_soc"} 1');

    for (const [key, val] of this.counters.entries()) {
      lines.push(`${key} ${val}`);
    }

    for (const [key, values] of this.histograms.entries()) {
      const metricName = key.split("{")[0];
      const sorted = [...values].sort((a, b) => a - b);
      const bucketLine = (le: string, count: number) => {
        const labels = key.includes("{") ? `${key.slice(key.indexOf("{") + 1, -1)},le="${le}"` : `le="${le}"`;
        lines.push(`${metricName}_bucket{${labels}} ${count}`);
      };
      for (const boundary of this.latencyBucketsMs) bucketLine(String(boundary), sorted.filter((value) => value <= boundary).length);
      bucketLine("+Inf", sorted.length);
      lines.push(`${metricName}_sum ${values.reduce((sum, value) => sum + value, 0)}`);
      lines.push(`${metricName}_count ${values.length}`);
    }

    return lines.join("\n");
  }

  public static clear(): void {
    this.counters.clear();
    this.histograms.clear();
  }

  private static serializeKey(name: string, labels: Record<string, string>): string {
    const labelEntries = Object.entries(labels);
    if (labelEntries.length === 0) return name;
    const labelStr = labelEntries.map(([k, v]) => `${k}="${String(v).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, "\\\"")}"`).join(",");
    return `${name}{${labelStr}}`;
  }
}
