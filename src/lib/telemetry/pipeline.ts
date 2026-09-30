import { CanonicalTelemetryEvent, TelemetryIngestContext, TelemetryBatchResult } from "./types";
import { TelemetryNormalizer } from "./normalizer";

export class TelemetryPipeline {
  private static buffer: Map<string, CanonicalTelemetryEvent[]> = new Map();

  public static async processBatch(
    events: Array<Record<string, unknown>>,
    context: TelemetryIngestContext
  ): Promise<TelemetryBatchResult> {
    let ingestedCount = 0;
    let duplicateCount = 0;
    let droppedCount = 0;
    const deadLetterEvents: Array<{ event: unknown; error: string }> = [];
    const ingestedEvents: CanonicalTelemetryEvent[] = [];

    const tenantBuffer = this.buffer.get(context.tenantId) || [];
    const seenFingerprints = new Set(tenantBuffer.map((e) => e.fingerprint));

    for (const raw of events) {
      try {
        const canonical = TelemetryNormalizer.normalize(raw, context);
        if (seenFingerprints.has(canonical.fingerprint)) {
          duplicateCount++;
          continue;
        }

        seenFingerprints.add(canonical.fingerprint);
        tenantBuffer.push(canonical);
        ingestedEvents.push(canonical);
        ingestedCount++;

        // Keep buffer bounded (last 1000 events per tenant)
        if (tenantBuffer.length > 1000) {
          tenantBuffer.shift();
        }
      } catch (err: unknown) {
        droppedCount++;
        deadLetterEvents.push({
          event: raw,
          error: err instanceof Error ? err.message : "Normalization failure",
        });
      }
    }

    this.buffer.set(context.tenantId, tenantBuffer);

    return {
      success: true,
      ingestedCount,
      duplicateCount,
      droppedCount,
      deadLetterEvents,
      detectionsCount: 0,
      detections: [],
      events: ingestedEvents,
    };
  }

  public static getEvents(tenantId: string, limit = 100): CanonicalTelemetryEvent[] {
    const list = this.buffer.get(tenantId) || [];
    return list.slice(-limit);
  }

  public static clear(tenantId?: string): void {
    if (tenantId) {
      this.buffer.delete(tenantId);
    } else {
      this.buffer.clear();
    }
  }
}