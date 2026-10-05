/**
 * ShieldDesk Phase A — OpenVAS / Greenbone Connector (Full SDK implementation)
 *
 * OpenVAS (Greenbone Vulnerability Manager) is the primary network vulnerability
 * scanner integrated into ShieldDesk's data layer.
 *
 * Protocol:
 *   - OpenVAS exposes a REST API via Greenbone Security Assistant (GSA) on port 9390/443.
 *   - Authentication: username/password → session token (stored in Cookie).
 *   - Collection: GET /api/v1/reports (JSON format) with cursor = last report date.
 *   - Scan results include network-reachable CVEs, CVSS scores, and NVT OIDs.
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
  FindingContext,
  ExtendedConnectorType,
} from "./event-model";
import { ConnectorAuthError } from "./event-model";

interface OpenVASResult {
  id?: string;
  name?: string;
  description?: string;
  nvt?: {
    oid?: string;
    name?: string;
    cvss_base?: string;
    solution_type?: string;
    cve_id?: string;
  };
  host?: { ip?: string; hostname?: string };
  port?: string;
  threat?: string;
  severity?: string | number;
  qod?: { value?: number };
  solution?: { text?: string };
}

interface OpenVASReport {
  id?: string;
  start?: string;
  end?: string;
  task?: { name?: string };
  results?: OpenVASResult[];
}

export class OpenVASConnector implements ISecurityConnector {
  readonly connectorType: ExtendedConnectorType = "openvas";
  readonly displayName = "OpenVAS / Greenbone Network Scanner";

  private baseUrl = "";
  private sessionToken: string | null = null;
  private cursor = new Date(0).toISOString();

  // ── SDK: healthCheck ───────────────────────────────────────────────────────
  async healthCheck(baseUrl: string, creds: ConnectorCredentials): Promise<ConnectorHealthResult> {
    const start = Date.now();
    try {
      const res = await fetch(`${baseUrl}/api/v1/info`, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(5000),
      });

      if (res.status === 401 || res.status === 403) {
        return {
          healthy: false,
          status: "auth_failed",
          message: "OpenVAS API rejected the request (HTTP 401/403)",
          latencyMs: Date.now() - start,
          checkedAt: new Date().toISOString(),
        };
      }
      if (!res.ok) {
        return {
          healthy: false,
          status: "unreachable",
          message: `OpenVAS returned HTTP ${res.status}`,
          latencyMs: Date.now() - start,
          checkedAt: new Date().toISOString(),
        };
      }
      return {
        healthy: true,
        status: "healthy",
        message: "OpenVAS API is reachable",
        latencyMs: Date.now() - start,
        checkedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        healthy: false,
        status: "unreachable",
        message: `OpenVAS health check failed: ${err instanceof Error ? err.message : String(err)}`,
        latencyMs: Date.now() - start,
        checkedAt: new Date().toISOString(),
      };
    }
  }

  // ── SDK: authenticate ──────────────────────────────────────────────────────
  async authenticate(baseUrl: string, creds: ConnectorCredentials): Promise<void> {
    this.baseUrl = baseUrl;

    const username = creds.username;
    const password = creds.password;
    if (!username || !password) {
      throw new ConnectorAuthError("OpenVAS requires basic credentials (username + password)");
    }

    const res = await fetch(`${this.baseUrl}/api/v1/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ username, password }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      throw new ConnectorAuthError(`OpenVAS authentication failed: HTTP ${res.status}`);
    }

    const body = (await res.json()) as { token?: string };
    const token = body.token;
    if (!token) {
      throw new ConnectorAuthError("OpenVAS did not return a session token");
    }
    this.sessionToken = token;
  }

  // ── SDK: collect ──────────────────────────────────────────────────────────
  async collect(tenantId: string, opts: CollectOptions): Promise<CollectResult> {
    if (!this.sessionToken) {
      throw new ConnectorAuthError("OpenVAS: not authenticated — call authenticate() first");
    }

    const after = opts.cursor ?? this.cursor;
    const url = `${this.baseUrl}/api/v1/reports?filter=rows=${opts.maxEvents ?? 500}&filter=first=1&filter=created>${after}`;

    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.sessionToken}`,
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) {
      throw new Error(`OpenVAS collect failed: HTTP ${res.status}`);
    }

    const body = (await res.json()) as { reports?: OpenVASReport[] };
    const reports = body.reports ?? [];

    const events: CanonicalSecurityEvent[] = [];
    let latestTimestamp = after;

    for (const report of reports) {
      const reportTs = report.end ?? report.start ?? new Date().toISOString();
      if (reportTs > latestTimestamp) latestTimestamp = reportTs;

      for (const result of report.results ?? []) {
        try {
          const raw: Record<string, unknown> = {
            ...result,
            _reportId: report.id,
            _reportStart: report.start,
            _reportEnd: report.end,
            _taskName: report.task?.name,
          };
          const evt = this.normalize(raw, tenantId);
          const validation = this.validate(evt);
          if (validation.valid) {
            events.push(evt);
          }
        } catch {
          // Skip malformed individual results
        }
      }
    }

    this.cursor = latestTimestamp;

    return {
      events,
      nextCursor: this.cursor,
      hasMore: reports.length >= (opts.maxEvents ?? 500),
      fetchedAt: new Date().toISOString(),
    };
  }

  // ── SDK: normalize ────────────────────────────────────────────────────────
  normalize(raw: Record<string, unknown>, tenantId: string): CanonicalSecurityEvent {
    const nvt = (raw.nvt as OpenVASResult["nvt"]) ?? {};
    const host = (raw.host as OpenVASResult["host"]) ?? {};
    const qod = (raw.qod as { value?: number }) ?? {};
    const solution = (raw.solution as { text?: string }) ?? {};

    const cveId = nvt.cve_id ?? "";
    const hostname = host.hostname ?? host.ip ?? "unknown-host";
    const ip = host.ip ?? "";
    const nvtOid = nvt.oid ?? "";

    const rawSeverity = String(raw.severity ?? raw.threat ?? "0");
    const cvssScore = parseFloat(rawSeverity);

    let severity: CanonicalSecurityEvent["severity"] = "info";
    if (cvssScore >= 9.0) severity = "critical";
    else if (cvssScore >= 7.0) severity = "high";
    else if (cvssScore >= 4.0) severity = "medium";
    else if (cvssScore > 0) severity = "low";

    const externalId = String(raw.id ?? nvtOid ?? `openvas-${Date.now()}`);
    const dedupInput = `${tenantId}|openvas|${cveId || nvtOid}|${hostname}|${String(raw.port ?? "")}`;
    const dedupFingerprint = crypto.createHash("sha256").update(dedupInput).digest("hex");
    const id = `sec-evt-${dedupFingerprint.slice(0, 16)}`;

    const vulnerability: VulnerabilityIntelligence | undefined = cveId
      ? {
          cveId,
          cvssScore: !isNaN(cvssScore) ? cvssScore : undefined,
          kevListed: false,
          vendorSeverity: String(raw.threat ?? ""),
        }
      : undefined;

    const finding: FindingContext = {
      findingId: nvtOid || externalId,
      component: nvt.name ?? String(raw.name ?? ""),
      remediationText: solution.text ?? undefined,
      confidence: qod.value !== undefined ? qod.value / 100 : undefined,
      hasExploitEvidence: String(raw.threat ?? "").toLowerCase() === "high",
    };

    return {
      id,
      tenantId,
      source: "openvas",
      externalId,
      dedupFingerprint,
      timestamp: String(raw._reportEnd ?? raw._reportStart ?? new Date().toISOString()),
      ingestAt: new Date().toISOString(),
      severity,
      category: "vulnerability",
      eventType: "network_vulnerability_finding",
      title: String(raw.name ?? nvt.name ?? `OpenVAS finding on ${hostname}`),
      description: String(
        raw.description ?? `OpenVAS NVT ${nvtOid} on ${hostname}:${String(raw.port ?? "")}`
      ),
      affectedAsset: {
        hostname,
        ip,
      },
      vulnerability,
      findingContext: finding,
      networkContext: {
        dstIp: ip,
        dstPort: raw.port ? parseInt(String(raw.port).split("/")[0], 10) || undefined : undefined,
        protocol: raw.port
          ? (String(raw.port).split("/")[1]?.toLowerCase() as "tcp" | "udp") || undefined
          : undefined,
      },
      status: "open",
      tags: ["openvas", "network-scan", "vulnerability", severity],
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
    if (!event.dedupFingerprint) errors.push("Missing dedupFingerprint");
    if (!event.affectedAsset.hostname && !event.affectedAsset.ip)
      errors.push("OpenVAS event missing both hostname and ip");
    if (event.severity === "info" && !event.findingContext?.findingId)
      warnings.push("Info-severity event has no findingId");

    return { valid: errors.length === 0, errors, warnings };
  }

  // ── SDK: getCursor ────────────────────────────────────────────────────────
  getCursor(): string {
    return this.cursor;
  }

  // ── SDK: disconnect ───────────────────────────────────────────────────────
  async disconnect(): Promise<void> {
    this.sessionToken = null;
  }
}
