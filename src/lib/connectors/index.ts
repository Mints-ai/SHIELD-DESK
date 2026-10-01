/**
 * ShieldDesk Connector Library — Public API
 *
 * Phase A adds:
 * - Canonical extended event model (CVSS/EPSS/KEV/asset criticality)
 * - Full ISecurityConnector SDK interface
 * - WazuhConnector (full SDK, offset cursor)
 * - TrivyConnector (push-based SCA, HMAC verification)
 * - OpenVASConnector (timestamp cursor, network findings)
 * - AssetCriticalityService (deterministic rule-based classification)
 * - EventDeduplicator (SHA-256 fingerprint + time window)
 * - FindingCorrelator (deterministic CVE campaign / ransomware / lateral movement)
 *
 * Legacy exports preserved for backwards compatibility.
 */

// Legacy (Phase 22 / existing tests) — unchanged
export { ConnectorNormalizer } from "./normalizer";
export { ConnectorRegistry } from "./registry";
export type { ConnectorType, EventSeverity, NormalizedAssetRef, UniversalSecurityEvent, IngestConnectorResult } from "./types";

// Phase A — canonical event model
export * from "./event-model";

// Phase A — connectors
export { WazuhConnector } from "./wazuh";
export { TrivyConnector } from "./trivy";
export { OpenVASConnector } from "./openvas";

// Phase A — enrichment and dedup
export { AssetCriticalityService } from "./asset-criticality";
export { EventDeduplicator, FindingCorrelator } from "./deduplication";
export type { DeduplicationResult, CorrelatedFinding, FindingCategory } from "./deduplication";
