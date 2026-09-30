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

  public static increment(name: string, value = 1, labels: Record<string, string> = {}): void {
    const key = this.serializeKey(name, labels);
    const curr = this.counters.get(key) || 0;
    this.counters.set(key, curr + value);
  }

  public static observe(name: string, value: number, labels: Record<string, string> = {}): void {
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

    return lines.join("\n");
  }

  public static clear(): void {
    this.counters.clear();
    this.histograms.clear();
  }

  private static serializeKey(name: string, labels: Record<string, string>): string {
    const labelEntries = Object.entries(labels);
    if (labelEntries.length === 0) return name;
    const labelStr = labelEntries.map(([k, v]) => `${k}="${v}"`).join(",");
    return `${name}{${labelStr}}`;
  }
}
