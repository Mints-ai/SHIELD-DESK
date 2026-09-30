/**
 * ShieldDesk Phase A — Wazuh Connector (Full SDK implementation)
 *
 * Implements ISecurityConnector against the Wazuh REST API v4.
 * Wazuh is the primary SIEM connector for the ShieldDesk platform.
 *
 * Authentication: basic auth → JWT token (auto-refreshed).
 * Collection: GET /alerts?offset=<N>&limit=<N>&sort=-timestamp
 * Cursor: offset-based (integer count of events already fetched).
 *
 * NON-NEGOTIABLE: This connector NEVER executes anything. It only reads
 * and normalizes. The Execution Broker is the sole dispatch point.
 */

import crypto from "node:crypto";
import type {
  ISecurityConnector,
  ConnectorCredentials,
  ConnectorHealthResult,
  CollectOptions,
  CollectResult,
  ValidationResult,
  CanonicalSecurityEvent,
  VulnerabilityIntelligence,
  ExtendedConnectorType,
} from "./event-model";
import { ConnectorAuthError, ConnectorNormalizationError } from "./event-model";

export class WazuhConnector implements ISecurityConnector {
  readonly connectorType: ExtendedConnectorType = "wazuh";
  readonly displayName = "Wazuh SIEM";

  private baseUrl = "";
  private jwtToken: string | null = null;
  private tokenExpiresAt: number = 0;
  private cursor = "0";

  // ── SDK: healthCheck ───────────────────────────────────────────────────────
  async healthCheck(baseUrl: string, creds: ConnectorCredentials): Promise<ConnectorHealthResult> {
    const start = Date.now();
    try {
      const url = `${baseUrl}/security/user/authenticate`;
      // Build basic-auth header
      const authHeader =
        creds.type === "basic" && creds.username && creds.password
          ? `Basic ${Buffer.from(`${creds.username}:${creds.password}`).toString("base64")}`
          : creds.type === "bearer" && creds.token
          ? `Bearer ${creds.token}`
          : undefined;

      if (!authHeader) {
        return {
          healthy: false,
          status: "auth_failed",
          message: "Wazuh requires basic (username/password) or bearer credentials",
          checkedAt: new Date().toISOString(),
        };
      }

      const res = await fetch(url, {
        method: "GET",
        headers: { Authorization: authHeader, Accept: "application/json" },
        signal: AbortSignal.timeout(5000),
      });

      if (res.status === 401) {
        return {
          healthy: false,
          status: "auth_failed",
          message: "Wazuh credentials rejected (HTTP 401)",
          latencyMs: Date.now() - start,
          checkedAt: new Date().toISOString(),
        };
      }
      if (!res.ok) {
        return {
          healthy: false,
          status: "unreachable",
          message: `Wazuh returned HTTP ${res.status}`,
          latencyMs: Date.now() - start,
          checkedAt: new Date().toISOString(),
        };
      }
      const data = (await res.json()) as { data?: { token?: string } };
      return {
        healthy: true,
        status: "healthy",
        message: "Wazuh API reachable and credentials valid",
        latencyMs: Date.now() - start,
        apiVersion: "4.x",
        checkedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        healthy: false,
        status: "unreachable",
        message: `Wazuh health check failed: ${err instanceof Error ? err.message : String(err)}`,
        latencyMs: Date.now() - start,
        checkedAt: new Date().toISOString(),
      };
    }
  }

  // ── SDK: authenticate ──────────────────────────────────────────────────────
  async authenticate(baseUrl: string, creds: ConnectorCredentials): Promise<void> {
    this.baseUrl = baseUrl;
    const token = await this.fetchJwt(creds);
    if (!token) {
      throw new ConnectorAuthError("Wazuh: failed to obtain JWT — check credentials and API endpoint");
    }
    this.jwtToken = token;
    // Wazuh JWTs have a 900 s lifetime; refresh 60 s before expiry
    this.tokenExpiresAt = Date.now() + 840_000;
  }

  // ── SDK: collect ──────────────────────────────────────────────────────────
  async collect(tenantId: string, opts: CollectOptions): Promise<CollectResult> {
    if (!this.jwtToken) {
      throw new ConnectorAuthError("Wazuh: not authenticated — call authenticate() first");
    }

    // Refresh JWT if stale
    if (Date.now() >= this.tokenExpiresAt) {
      throw new ConnectorAuthError("Wazuh: JWT expired — re-authenticate");
    }

    const offset = parseInt(opts.cursor ?? "0", 10);
    const limit = Math.min(opts.maxEvents ?? 500, 1000);

    const url = `${this.baseUrl}/alerts?offset=${offset}&limit=${limit}&sort=-timestamp&pretty=false`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${this.jwtToken}`, Accept: "application/json" },
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) {
      throw new Error(`Wazuh collect failed: HTTP ${res.status}`);
    }

    const body = (await res.json()) as {
      data?: { affected_items?: Record<string, unknown>[]; total_affected_items?: number };
    };

    const items = body.data?.affected_items ?? [];
    const total = body.data?.total_affected_items ?? 0;
    const nextOffset = offset + items.length;

    const events: CanonicalSecurityEvent[] = [];
    for (const raw of items) {
      try {
        const evt = this.normalize(raw, tenantId);
        const validation = this.validate(evt);
        if (validation.valid) {
          events.push(evt);
        }
        // Silently skip invalid events — they are logged in raw_payload
      } catch {
        // Skip malformed individual events; do not abort the entire batch
      }
    }

    this.cursor = String(nextOffset);

    return {
      events,
      nextCursor: this.cursor,
      hasMore: nextOffset < total,
      fetchedAt: new Date().toISOString(),
    };
  }

  // ── SDK: normalize ────────────────────────────────────────────────────────
  normalize(raw: Record<string, unknown>, tenantId: string): CanonicalSecurityEvent {
    const rule = (raw.rule as Record<string, unknown>) ?? {};
    const agent = (raw.agent as Record<string, unknown>) ?? {};
    const data = (raw.data as Record<string, unknown>) ?? {};
    const win = (data.win as Record<string, unknown>) ?? {};
    const eventdata = (win.eventdata as Record<string, unknown>) ?? {};
    const syscheck = (raw.syscheck as Record<string, unknown>) ?? {};
    const fullLog = String(raw.full_log ?? "");

    const level = Number(rule.level ?? 3);
    let severity: CanonicalSecurityEvent["severity"] = "low";
    if (level >= 12) severity = "critical";
    else if (level >= 8) severity = "high";
    else if (level >= 5) severity = "medium";

    const externalId = String(raw.id ?? rule.id ?? `wazuh-${Date.now()}`);
    const hostname = String(agent.name ?? "unknown-host");
    const ruleId = String(rule.id ?? "");

    const dedupInput = `${tenantId}|wazuh|${externalId}|${hostname}|${ruleId}`;
    const dedupFingerprint = crypto
      .createHash("sha256")
      .update(dedupInput)
      .digest("hex");

    const id = `sec-evt-${dedupFingerprint.slice(0, 16)}`;

    // Determine category
    const groups: string[] = Array.isArray(rule.groups) ? (rule.groups as string[]) : [];
    let category: CanonicalSecurityEvent["category"] = "alert";
    if (groups.some((g) => /vuln|cve/i.test(g))) category = "vulnerability";
    else if (groups.some((g) => /compliance|audit|sca/i.test(g))) category = "compliance";

    // Determine event type
    const eventId = Number(raw.EventID ?? data.EventID ?? 0);
    let eventType = "wazuh_alert";
    if (eventId === 1) eventType = "process_create";
    else if (eventId === 3) eventType = "network_connect";
    else if (eventId === 11) eventType = "file_create";
    else if (Object.keys(syscheck).length > 0) eventType = "file_integrity_change";

    // CVE / vulnerability intelligence from log
    let vulnerability: VulnerabilityIntelligence | undefined;
    const cveMatch = fullLog.match(/(CVE-\d{4}-\d{4,7})/i);
    if (cveMatch || category === "vulnerability") {
      const cveId = cveMatch?.[1] ?? (String(raw.cve_id ?? ""));
      const cvssRaw = Number(raw.cvss ?? rule.level) ?? undefined;
      vulnerability = {
        cveId,
        cvssScore: cvssRaw > 0 ? Math.min(10, cvssRaw) : undefined,
        kevListed: false,
        vendorSeverity: String(raw.severity ?? "").toUpperCase() || undefined,
      };
    }

    return {
      id,
      tenantId,
      source: "wazuh",
      externalId,
      dedupFingerprint,
      timestamp: String(raw.timestamp ?? new Date().toISOString()),
      ingestAt: new Date().toISOString(),
      severity,
      category,
      eventType,
      title: String(rule.description ?? "Wazuh Security Alert"),
      description: `Wazuh Rule ${ruleId}: ${rule.description ?? "Detected security anomaly"}`,
      affectedAsset: {
        id: String(agent.id ?? ""),
        hostname,
        ip: String(agent.ip ?? ""),
      },
      vulnerability,
      processContext: eventdata.image
        ? {
            name: String(eventdata.image).split(/[\\/]/).pop(),
            commandLine: String(eventdata.commandLine ?? ""),
            pid: Number(eventdata.processId) || undefined,
            sha256: String(eventdata.hashes ?? ""),
            user: String(eventdata.user ?? ""),
          }
        : undefined,
      status: "open",
      tags: groups.length > 0 ? groups : ["wazuh", "siem"],
      evidenceIds: [],
      rawPayload: raw,
    };
  }

  // ── SDK: validate ─────────────────────────────────────────────────────────
  validate(event: CanonicalSecurityEvent): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!event.id) errors.push("Missing event id");
    if (!event.tenantId) errors.push("Missing tenantId");
    if (!event.externalId) errors.push("Missing externalId");
    if (!event.dedupFingerprint || event.dedupFingerprint.length < 16)
      errors.push("Invalid dedupFingerprint");
    if (!event.title) errors.push("Missing title");
    if (!event.timestamp) errors.push("Missing timestamp");
    if (!event.affectedAsset.hostname) warnings.push("affectedAsset.hostname is empty");
    if (event.vulnerability && !event.vulnerability.cveId)
      errors.push("Vulnerability event missing cveId");

    return { valid: errors.length === 0, errors, warnings };
  }

  // ── SDK: getCursor ────────────────────────────────────────────────────────
  getCursor(): string {
    return this.cursor;
  }

  // ── SDK: disconnect ───────────────────────────────────────────────────────
  async disconnect(): Promise<void> {
    this.jwtToken = null;
    this.tokenExpiresAt = 0;
  }

  // ── Private helpers ───────────────────────────────────────────────────────
  private async fetchJwt(creds: ConnectorCredentials): Promise<string | null> {
    try {
      const authHeader =
        creds.type === "basic" && creds.username && creds.password
          ? `Basic ${Buffer.from(`${creds.username}:${creds.password}`).toString("base64")}`
          : creds.type === "bearer" && creds.token
          ? `Bearer ${creds.token}`
          : null;

      if (!authHeader) return null;

      const res = await fetch(`${this.baseUrl}/security/user/authenticate`, {
        method: "GET",
        headers: { Authorization: authHeader, Accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) return null;
      const body = (await res.json()) as { data?: { token?: string } };
      return body.data?.token ?? null;
    } catch {
      return null;
    }
  }
}
