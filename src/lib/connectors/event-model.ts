/**
 * ShieldDesk Phase A — Universal Security Event Model
 *
 * This file is the canonical type contract for all security events flowing
 * through the ShieldDesk platform, regardless of source.
 *
 * Design principles:
 * - Source-agnostic: Wazuh, Trivy, OpenVAS, Defender, CrowdStrike all produce
 *   the same type after normalization.
 * - Evidence-first: every event carries its evidence chain and dedup fingerprint.
 * - Criticality-aware: asset and business criticality drive risk scoring.
 *
 * BACKWARD COMPATIBLE: The legacy `ConnectorType` and `UniversalSecurityEvent`
 * types from `./types.ts` are preserved unchanged. This module extends them.
 */

// Re-export legacy types so existing imports keep working
export type {
  ConnectorType,
  EventSeverity,
  NormalizedAssetRef,
  UniversalSecurityEvent,
  IngestConnectorResult,
} from "./types";

// ──────────────────────────────────────────────────────────────────────────────
// Extended source registry (Phase A adds trivy and openvas)
// ──────────────────────────────────────────────────────────────────────────────
export type ExtendedConnectorType =
  | "wazuh"
  | "trivy"
  | "openvas"
  | "defender"
  | "crowdstrike"
  | "webhook"
  | "generic_siem";

// ──────────────────────────────────────────────────────────────────────────────
// Asset and business criticality
// ──────────────────────────────────────────────────────────────────────────────
export type AssetCriticality = "critical" | "high" | "medium" | "low";
export type BusinessImpact = "revenue" | "compliance" | "operational" | "reputational" | "low";

export interface AssetCriticalityProfile {
  criticality: AssetCriticality;
  businessImpact: BusinessImpact;
  /** Estimated annual business value in USD — used by blast-radius engine */
  businessValueUsd?: number;
  justification: string;
}

// ──────────────────────────────────────────────────────────────────────────────
// Vulnerability Intelligence
// ──────────────────────────────────────────────────────────────────────────────
export interface VulnerabilityIntelligence {
  cveId: string;
  /** CVSS base score (v3.1 preferred) */
  cvssScore?: number;
  /** Full CVSS vector string e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H */
  cvssVector?: string;
  /** EPSS probability of exploitation (0.0 – 1.0) */
  epssScore?: number;
  /** EPSS percentile rank (0 – 100) */
  epssPercentile?: number;
  /** True if present in CISA Known Exploited Vulnerabilities catalogue */
  kevListed: boolean;
  /** Date CVE was added to KEV catalogue */
  kevDateAdded?: string;
  /** Raw severity label from the vendor (e.g. "CRITICAL", "High") */
  vendorSeverity?: string;
  /** Package or component affected */
  packageName?: string;
  /** Installed version string */
  installedVersion?: string;
  /** Fixed / patched version available */
  fixedVersion?: string;
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding context (vulnerability scanners)
// ──────────────────────────────────────────────────────────────────────────────
export interface FindingContext {
  /** Scanner-specific finding identifier */
  findingId?: string;
  /** Affected component: package, service, file, or configuration item */
  component?: string;
  /** Path to the affected resource */
  resourcePath?: string;
  /** Remediation advice text from the scanner */
  remediationText?: string;
  /** Scanner confidence score (0.0 – 1.0) */
  confidence?: number;
  /** Whether the scanner confirmed active exploitation evidence */
  hasExploitEvidence?: boolean;
  /** Related Mitre ATT&CK technique IDs */
  mitreTechniques?: string[];
}

// ──────────────────────────────────────────────────────────────────────────────
// Canonical Extended Security Event (Phase A model)
// ──────────────────────────────────────────────────────────────────────────────
export type EventCategory =
  | "alert"
  | "vulnerability"
  | "compliance"
  | "anomaly"
  | "audit";

export interface CanonicalSecurityEvent {
  /** Stable UUID assigned at ingest time */
  id: string;
  tenantId: string;
  source: ExtendedConnectorType;
  externalId: string;
  /** SHA-256 deduplication fingerprint: tenant+source+externalId+assetHostname+ruleId */
  dedupFingerprint: string;
  timestamp: string;
  ingestAt: string;

  severity: "critical" | "high" | "medium" | "low" | "info";
  category: EventCategory;
  eventType: string;
  title: string;
  description: string;

  /** Enriched asset reference with criticality profile */
  affectedAsset: {
    id?: string;
    hostname?: string;
    ip?: string;
    os?: string;
    criticality?: AssetCriticality;
    businessImpact?: BusinessImpact;
  };

  /** Vulnerability intelligence — populated for CVE findings */
  vulnerability?: VulnerabilityIntelligence;

  /** Scanner-specific finding details */
  findingContext?: FindingContext;

  processContext?: {
    name?: string;
    pid?: number;
    commandLine?: string;
    sha256?: string;
    user?: string;
  };
  networkContext?: {
    srcIp?: string;
    dstIp?: string;
    dstPort?: number;
    protocol?: string;
  };

  /** Finding lifecycle status */
  status: "open" | "investigating" | "remediated" | "closed" | "suppressed" | "false_positive";

  /** Linked incident ID if correlated */
  incidentId?: string;
  /** When to run the next automatic recheck */
  recheckAt?: string;

  tags: string[];
  /** References into hash_chain_audit */
  evidenceIds: string[];
  rawPayload: Record<string, unknown>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Connector SDK Interface
// ──────────────────────────────────────────────────────────────────────────────

export interface ConnectorCredentials {
  type: "api_key" | "basic" | "bearer" | "oauth2" | "mtls";
  apiKey?: string;
  username?: string;
  password?: string;
  token?: string;
  certPem?: string;
  keyPem?: string;
}

export interface ConnectorHealthResult {
  healthy: boolean;
  /** One of the standard health state labels */
  status: "healthy" | "degraded" | "unreachable" | "auth_failed" | "unknown";
  message: string;
  latencyMs?: number;
  apiVersion?: string;
  checkedAt: string;
}

export interface CollectOptions {
  /** Opaque cursor from last successful collect. Null on first run. */
  cursor?: string | null;
  maxEvents?: number;
}

export interface CollectResult {
  events: CanonicalSecurityEvent[];
  /** New cursor to persist for the next collect call */
  nextCursor: string;
  hasMore: boolean;
  fetchedAt: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Connector SDK — every connector MUST implement all seven methods.
 * This is the contract the registry uses regardless of vendor.
 */
export interface ISecurityConnector {
  readonly connectorType: ExtendedConnectorType;
  readonly displayName: string;

  /**
   * Verifies credentials and connectivity.
   * Must NOT store state; must be callable before authenticate().
   */
  healthCheck(baseUrl: string, creds: ConnectorCredentials): Promise<ConnectorHealthResult>;

  /**
   * Validates and stores credentials for use by collect().
   * Returns true on success; throws ConnectorAuthError on failure.
   */
  authenticate(baseUrl: string, creds: ConnectorCredentials): Promise<void>;

  /**
   * Fetches and normalizes raw vendor events using the stored cursor.
   * MUST be idempotent for the same cursor value.
   */
  collect(tenantId: string, opts: CollectOptions): Promise<CollectResult>;

  /**
   * Normalizes a single raw vendor payload into CanonicalSecurityEvent.
   * Pure function — no side effects, no network calls.
   */
  normalize(raw: Record<string, unknown>, tenantId: string): CanonicalSecurityEvent;

  /**
   * Validates a normalized event for completeness and consistency.
   * Called after normalize() before the event is persisted.
   */
  validate(event: CanonicalSecurityEvent): ValidationResult;

  /**
   * Returns the current cursor value for persistence.
   * Called after every successful collect().
   */
  getCursor(): string;

  /**
   * Gracefully terminates any open connections or polling sessions.
   */
  disconnect(): Promise<void>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

export class ConnectorAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConnectorAuthError";
  }
}

export class ConnectorNormalizationError extends Error {
  constructor(message: string, public readonly raw?: unknown) {
    super(message);
    this.name = "ConnectorNormalizationError";
  }
}
