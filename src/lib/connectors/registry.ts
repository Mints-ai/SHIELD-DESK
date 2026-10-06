import crypto from "node:crypto";
import { ConnectorNormalizer } from "./normalizer";
import { ConnectorType, IngestConnectorResult, UniversalSecurityEvent } from "./types";
import { MetricsRegistry } from "@/lib/observability/metrics";

export class ConnectorRegistry {
  private static events: Map<string, UniversalSecurityEvent[]> = new Map();

  /**
   * Ingests, normalizes, and verifies security events from external security vendors.
   */
  public static async ingest(
    source: ConnectorType,
    payload: Record<string, unknown>,
    tenantId: string,
    options: {
      signatureHeader?: string;
      secretKey?: string;
    } = {}
  ): Promise<IngestConnectorResult> {
    if (!tenantId) {
      MetricsRegistry.increment("shielddesk_connector_errors_total", 1, { source, reason: "missing_tenant" });
      return { success: false, error: "Missing required tenant context" };
    }

    // Verify HMAC signature if secret is configured
    if (options.secretKey && options.signatureHeader) {
      const computed = crypto
        .createHmac("sha256", options.secretKey)
        .update(JSON.stringify(payload))
        .digest("hex");

      const expected = options.signatureHeader.replace(/^sha256=/, "");
      if (computed !== expected) {
        MetricsRegistry.increment("shielddesk_connector_errors_total", 1, { source, reason: "signature" });
        return { success: false, error: "Cryptographic HMAC webhook signature mismatch" };
      }
    }

    let event: UniversalSecurityEvent;
    try {
      switch (source) {
        case "wazuh":
          event = ConnectorNormalizer.normalizeWazuh(payload, tenantId);
          break;
        case "defender":
          event = ConnectorNormalizer.normalizeDefender(payload, tenantId);
          break;
        case "crowdstrike":
          event = ConnectorNormalizer.normalizeCrowdStrike(payload, tenantId);
          break;
        case "webhook":
        case "generic_siem":
        default:
          event = ConnectorNormalizer.normalizeGenericWebhook(payload, tenantId);
          break;
      }
    } catch (err: unknown) {
      MetricsRegistry.increment("shielddesk_connector_errors_total", 1, { source, reason: "normalization" });
      return {
        success: false,
        error: `Connector normalization failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // Store in tenant event buffer
    if (!this.events.has(tenantId)) {
      this.events.set(tenantId, []);
    }
    const tenantList = this.events.get(tenantId)!;
    tenantList.push(event);
    MetricsRegistry.increment("shielddesk_connector_events_ingested_total", 1, { source });

    // Bounded buffer
    if (tenantList.length > 500) {
      tenantList.shift();
    }

    return { success: true, event };
  }

  public static getEvents(tenantId: string): UniversalSecurityEvent[] {
    return this.events.get(tenantId) || [];
  }

  public static clear(tenantId?: string): void {
    if (tenantId) {
      this.events.delete(tenantId);
    } else {
      this.events.clear();
    }
  }
}
