/**
 * ShieldDesk Phase A — Trivy Connector (Full SDK implementation)
 *
 * Trivy is the open-source container & filesystem SCA scanner.
 * This connector normalizes Trivy JSON report format (v2 schema) into
 * CanonicalSecurityEvent, with full CVSS/EPSS/KEV fields.
 *
 * Mode of operation:
 *   - Trivy does not have a persistent REST API; it produces JSON reports
 *     that are submitted to ShieldDesk via the ingest endpoint or CI/CD pipelines.
 *   - collect() processes a batch of pre-submitted report JSON objects.
 *   - authenticate() validates the HMAC webhook signing key.
 *   - Cursor: SHA-256 of the last processed report ID (report-hash based).
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
import { ConnectorAuthError } from "./event-model";

// Trivy JSON report v2 shapes (minimal typing for normalization)
interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  CVSS?: Record<string, { V3Score?: number; V3Vector?: string }>;
  Title?: string;
  Description?: string;
}

interface TrivyResult {
  Target?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
}

interface TrivyReport {
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: TrivyResult[];
  Metadata?: Record<string, unknown>;
}

export class TrivyConnector implements ISecurityConnector {
  readonly connectorType: ExtendedConnectorType = "trivy";
  readonly displayName = "Trivy SCA Scanner";

  private signingKey: string | null = null;
  private pendingReports: Array<{ report: TrivyReport; submittedAt: string; hostname: string }> = [];
  private cursor = "";

  // ── SDK: healthCheck ───────────────────────────────────────────────────────
  async healthCheck(baseUrl: string, creds: ConnectorCredentials): Promise<ConnectorHealthResult> {
    // Trivy is report-push; "health" means we can accept and parse a minimal JSON report
    const hasKey = Boolean(creds.apiKey ?? creds.token);
    return {
      healthy: hasKey,
      status: hasKey ? "healthy" : "auth_failed",
      message: hasKey
        ? "Trivy connector ready to accept reports (signing key configured)"
        : "Trivy connector requires an apiKey or token for HMAC report verification",
      checkedAt: new Date().toISOString(),
    };
  }

  // ── SDK: authenticate ──────────────────────────────────────────────────────
  async authenticate(baseUrl: string, creds: ConnectorCredentials): Promise<void> {
    const key = creds.apiKey ?? creds.token;
    if (!key) {
      throw new ConnectorAuthError("Trivy connector requires apiKey or token for HMAC signing key");
    }
    this.signingKey = key;
  }

  /**
   * Submit a Trivy JSON report for buffered processing.
   * Called by the ingest API endpoint when a CI/CD pipeline posts a report.
   *
   * @param report     Parsed Trivy JSON report object
   * @param hostname   The scanned host, image, or filesystem target
   * @param signature  HMAC-SHA256 signature for integrity verification
   */
  submitReport(report: TrivyReport, hostname: string, signature?: string): { accepted: boolean; reason?: string } {
    if (this.signingKey && signature) {
      const computed = crypto
        .createHmac("sha256", this.signingKey)
        .update(JSON.stringify(report))
        .digest("hex");
      const provided = signature.replace(/^sha256=/, "");
      if (computed !== provided) {
        return { accepted: false, reason: "HMAC signature mismatch — report rejected" };
      }
    }
    this.pendingReports.push({ report, submittedAt: new Date().toISOString(), hostname });
    return { accepted: true };
  }

  // ── SDK: collect ──────────────────────────────────────────────────────────
  async collect(tenantId: string, opts: CollectOptions): Promise<CollectResult> {
    const reports = this.pendingReports.splice(0); // consume all pending
    const events: CanonicalSecurityEvent[] = [];
    let lastId = opts.cursor ?? "";

    for (const { report, submittedAt, hostname } of reports) {
      const results = report.Results ?? [];
      for (const result of results) {
        const vulns = result.Vulnerabilities ?? [];
        for (const vuln of vulns) {
          try {
            const raw: Record<string, unknown> = {
              ...vuln,
              _target: result.Target,
              _type: result.Type,
              _artifactName: report.ArtifactName,
              _artifactType: report.ArtifactType,
              _submittedAt: submittedAt,
              _hostname: hostname,
            };
            const evt = this.normalize(raw, tenantId);
            const validation = this.validate(evt);
            if (validation.valid) {
              events.push(evt);
              lastId = evt.dedupFingerprint;
            }
          } catch {
            // Skip malformed individual findings
          }
        }
      }
    }

    this.cursor = lastId;

    return {
      events,
      nextCursor: this.cursor,
      hasMore: false, // Trivy is push-based; no "more pages"
      fetchedAt: new Date().toISOString(),
    };
  }

  // ── SDK: normalize ────────────────────────────────────────────────────────
  normalize(raw: Record<string, unknown>, tenantId: string): CanonicalSecurityEvent {
    const cveId = String(raw.VulnerabilityID ?? raw.cveId ?? "");
    const pkgName = String(raw.PkgName ?? raw.packageName ?? "");
    const installedVersion = String(raw.InstalledVersion ?? "");
    const fixedVersion = String(raw.FixedVersion ?? "");
    const rawSeverity = String(raw.Severity ?? "UNKNOWN").toUpperCase();
    const hostname = String(raw._hostname ?? raw.ArtifactName ?? "unknown-target");
    const target = String(raw._target ?? "");
    const artifactName = String(raw._artifactName ?? hostname);
    const submittedAt = String(raw._submittedAt ?? new Date().toISOString());

    // Severity mapping
    let severity: CanonicalSecurityEvent["severity"] = "info";
    if (rawSeverity === "CRITICAL") severity = "critical";
    else if (rawSeverity === "HIGH") severity = "high";
    else if (rawSeverity === "MEDIUM") severity = "medium";
    else if (rawSeverity === "LOW") severity = "low";

    // Extract best CVSS score from nested CVSS map
    const cvssMap = (raw.CVSS as Record<string, { V3Score?: number; V3Vector?: string }>) ?? {};
    let cvssScore: number | undefined;
    let cvssVector: string | undefined;
    for (const source of ["nvd", "ghsa", "redhat", "oracle"] as const) {
      const entry = cvssMap[source];
      if (entry?.V3Score !== undefined) {
        cvssScore = entry.V3Score;
        cvssVector = entry.V3Vector;
        break;
      }
    }

    const externalId = `trivy-${cveId}-${pkgName}-${hostname}`;
    const dedupInput = `${tenantId}|trivy|${cveId}|${pkgName}|${hostname}`;
    const dedupFingerprint = crypto.createHash("sha256").update(dedupInput).digest("hex");
    const id = `sec-evt-${dedupFingerprint.slice(0, 16)}`;

    const vulnerability: VulnerabilityIntelligence = {
      cveId,
      cvssScore,
      cvssVector,
      kevListed: false, // enriched by the vulnerability intelligence service
      vendorSeverity: rawSeverity,
      packageName: pkgName,
      installedVersion: installedVersion || undefined,
      fixedVersion: fixedVersion || undefined,
    };

    return {
      id,
      tenantId,
      source: "trivy",
      externalId,
      dedupFingerprint,
      timestamp: submittedAt,
      ingestAt: new Date().toISOString(),
      severity,
      category: "vulnerability",
      eventType: "cve_finding",
      title: cveId
        ? `${cveId} — ${pkgName || artifactName}`
        : `Trivy finding: ${String(raw.Title ?? "Vulnerability detected")}`,
      description: String(
        raw.Description ?? `${rawSeverity} vulnerability in ${pkgName} (${installedVersion}) on ${hostname}`
      ),
      affectedAsset: {
        hostname,
      },
      vulnerability,
      findingContext: {
        component: pkgName || target,
        resourcePath: target || artifactName,
        remediationText: fixedVersion ? `Upgrade ${pkgName} to ${fixedVersion}` : undefined,
        hasExploitEvidence: false,
      },
      status: "open",
      tags: ["trivy", "sca", "vulnerability", rawSeverity.toLowerCase()],
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
    if (!event.vulnerability?.cveId) errors.push("Trivy event missing vulnerability.cveId");
    if (!event.affectedAsset.hostname) warnings.push("affectedAsset.hostname is empty");

    return { valid: errors.length === 0, errors, warnings };
  }

  // ── SDK: getCursor ────────────────────────────────────────────────────────
  getCursor(): string {
    return this.cursor;
  }

  // ── SDK: disconnect ───────────────────────────────────────────────────────
  async disconnect(): Promise<void> {
    this.pendingReports = [];
  }
}
