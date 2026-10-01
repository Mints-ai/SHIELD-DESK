/**
 * ShieldDesk Phase A — Event Deduplication & Finding Correlation Engine
 *
 * Two separate concerns:
 *
 * 1. DEDUPLICATION: Given a stream of CanonicalSecurityEvents, suppress events
 *    already seen within the dedup window to prevent alert storms.
 *    Dedup key = dedupFingerprint (SHA-256 of tenant+source+externalId+hostname+rule).
 *
 * 2. CORRELATION: Group related events into Findings — high-level aggregations
 *    representing a distinct security problem (e.g. all CVE-2024-3400 findings
 *    across multiple hosts → one correlated Finding).
 *
 * Design constraints:
 * - Deterministic: same inputs always produce same dedup/correlation results.
 * - No AI: AI is not involved in deduplication or correlation decisions.
 * - Fail-open on dedup: uncertain = allow (wrong dedup = duplicate alert; acceptable risk).
 * - Fail-closed on correlation: uncertain = separate finding (safer than wrong merge).
 */

import crypto from "node:crypto";
import type { CanonicalSecurityEvent } from "./event-model";

// ──────────────────────────────────────────────────────────────────────────────
// Deduplication
// ──────────────────────────────────────────────────────────────────────────────

export interface DeduplicationResult {
  /** Events that passed the dedup check (new or refreshed) */
  newEvents: CanonicalSecurityEvent[];
  /** Events suppressed as duplicates */
  suppressedCount: number;
  /** Fingerprints that were already seen */
  duplicateFingerprints: string[];
}

export class EventDeduplicator {
  /**
   * Per-tenant dedup state: fingerprint → first seen timestamp (ms epoch)
   * The dedup window is controlled by windowMs (default 24 hours).
   */
  private static seenFingerprints: Map<
    string,
    Map<string, number>
  > = new Map();

  /** Default dedup window: 24 hours (86,400,000 ms) */
  static deduplicate(
    tenantId: string,
    events: CanonicalSecurityEvent[],
    windowMs = 86_400_000
  ): DeduplicationResult {
    const now = Date.now();
    if (!this.seenFingerprints.has(tenantId)) {
      this.seenFingerprints.set(tenantId, new Map());
    }
    const seen = this.seenFingerprints.get(tenantId)!;

    // Evict expired entries
    for (const [fp, ts] of seen) {
      if (now - ts > windowMs) seen.delete(fp);
    }

    const newEvents: CanonicalSecurityEvent[] = [];
    const duplicateFingerprints: string[] = [];

    for (const event of events) {
      const fp = event.dedupFingerprint;
      if (seen.has(fp)) {
        duplicateFingerprints.push(fp);
      } else {
        seen.set(fp, now);
        newEvents.push(event);
      }
    }

    return {
      newEvents,
      suppressedCount: duplicateFingerprints.length,
      duplicateFingerprints,
    };
  }

  /** Forcibly expire a fingerprint (used after a finding is closed/resolved) */
  static expire(tenantId: string, fingerprint: string): void {
    this.seenFingerprints.get(tenantId)?.delete(fingerprint);
  }

  /** Clear all state (used in tests) */
  static clear(tenantId?: string): void {
    if (tenantId) {
      this.seenFingerprints.delete(tenantId);
    } else {
      this.seenFingerprints.clear();
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding Correlation
// ──────────────────────────────────────────────────────────────────────────────

export type FindingCategory =
  | "cve_campaign"      // same CVE across multiple hosts
  | "lateral_movement"  // authentication anomalies across multiple hosts
  | "ransomware_ioc"    // ransomware-specific process/file indicators
  | "mass_exploitation" // same exploit across 5+ hosts
  | "isolated_alert";   // single-host, no correlation pattern

export interface CorrelatedFinding {
  /** Stable ID derived from the finding key */
  findingId: string;
  tenantId: string;
  category: FindingCategory;
  /** Human-readable summary of the correlated finding */
  title: string;
  severity: CanonicalSecurityEvent["severity"];
  /** Number of distinct events correlated into this finding */
  eventCount: number;
  /** Distinct affected asset hostnames */
  affectedHostnames: string[];
  /** Primary CVE if applicable */
  cveId?: string;
  /** IDs of the source events */
  eventIds: string[];
  /** Overall risk score (0–100) — driven by CVSS, KEV, and spread */
  riskScore: number;
  /** Evidence IDs from the hash-chain audit */
  evidenceIds: string[];
  correlatedAt: string;
}

export class FindingCorrelator {
  /**
   * Correlate a batch of deduplicated CanonicalSecurityEvents into Findings.
   *
   * Correlation logic (deterministic, no AI):
   * 1. CVE campaign: ≥2 events sharing the same CVE ID
   * 2. Ransomware IoC: events tagged "ransomware" from any host
   * 3. Mass exploitation: ≥5 events with same rule/title pattern
   * 4. Lateral movement: ≥3 auth-failure events across ≥2 hostnames
   * 5. Isolated alert: everything else
   */
  static correlate(
    tenantId: string,
    events: CanonicalSecurityEvent[]
  ): CorrelatedFinding[] {
    const findings: CorrelatedFinding[] = [];

    // Group by CVE
    const byCve = new Map<string, CanonicalSecurityEvent[]>();
    // Group by title pattern
    const byTitle = new Map<string, CanonicalSecurityEvent[]>();
    // Auth failures
    const authFailures: CanonicalSecurityEvent[] = [];
    // Ransomware
    const ransomware: CanonicalSecurityEvent[] = [];

    for (const evt of events) {
      // CVE grouping
      if (evt.vulnerability?.cveId) {
        const cve = evt.vulnerability.cveId;
        if (!byCve.has(cve)) byCve.set(cve, []);
        byCve.get(cve)!.push(evt);
      }

      // Ransomware IoC
      if (evt.tags.some((t) => /ransomware|ransom/i.test(t))) {
        ransomware.push(evt);
      }

      // Auth failures
      if (
        evt.eventType === "auth_failure" ||
        evt.category === "alert" &&
        /brute.?force|failed.?login|auth.?fail/i.test(evt.title)
      ) {
        authFailures.push(evt);
      }

      // Title-pattern grouping
      const titleKey = evt.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 80);
      if (!byTitle.has(titleKey)) byTitle.set(titleKey, []);
      byTitle.get(titleKey)!.push(evt);
    }

    const handled = new Set<string>();

    // ── 1. CVE campaigns ────────────────────────────────────────────────────
    for (const [cveId, cveEvents] of byCve) {
      if (cveEvents.length < 2) continue;

      const hostnames = [...new Set(cveEvents.map((e) => e.affectedAsset.hostname ?? ""))];
      const topSeverity = this.topSeverity(cveEvents);
      const maxCvss = Math.max(0, ...cveEvents.map((e) => e.vulnerability?.cvssScore ?? 0));
      const kevListed = cveEvents.some((e) => e.vulnerability?.kevListed);
      const riskScore = this.computeRiskScore(maxCvss, kevListed, cveEvents.length);

      const findingKey = `cve-campaign|${tenantId}|${cveId}`;
      const findingId = `finding-${crypto.createHash("sha256").update(findingKey).digest("hex").slice(0, 16)}`;

      findings.push({
        findingId,
        tenantId,
        category: "cve_campaign",
        title: `${cveId} campaign detected across ${hostnames.length} host${hostnames.length > 1 ? "s" : ""}`,
        severity: topSeverity,
        eventCount: cveEvents.length,
        affectedHostnames: hostnames,
        cveId,
        eventIds: cveEvents.map((e) => e.id),
        riskScore,
        evidenceIds: cveEvents.flatMap((e) => e.evidenceIds),
        correlatedAt: new Date().toISOString(),
      });

      cveEvents.forEach((e) => handled.add(e.id));
    }

    // ── 2. Ransomware IoC ───────────────────────────────────────────────────
    if (ransomware.length > 0) {
      const hostnames = [...new Set(ransomware.map((e) => e.affectedAsset.hostname ?? ""))];
      const findingKey = `ransomware|${tenantId}|${ransomware[0].timestamp.slice(0, 13)}`;
      const findingId = `finding-${crypto.createHash("sha256").update(findingKey).digest("hex").slice(0, 16)}`;

      findings.push({
        findingId,
        tenantId,
        category: "ransomware_ioc",
        title: `Ransomware indicators detected on ${hostnames.length} host${hostnames.length > 1 ? "s" : ""}`,
        severity: "critical",
        eventCount: ransomware.length,
        affectedHostnames: hostnames,
        eventIds: ransomware.map((e) => e.id),
        riskScore: 95,
        evidenceIds: ransomware.flatMap((e) => e.evidenceIds),
        correlatedAt: new Date().toISOString(),
      });

      ransomware.forEach((e) => handled.add(e.id));
    }

    // ── 3. Mass exploitation ────────────────────────────────────────────────
    for (const [titleKey, titleEvents] of byTitle) {
      if (titleEvents.length < 5) continue;
      const unhanlded = titleEvents.filter((e) => !handled.has(e.id));
      if (unhanlded.length < 5) continue;

      const hostnames = [...new Set(unhanlded.map((e) => e.affectedAsset.hostname ?? ""))];
      const findingKey = `mass-exploit|${tenantId}|${titleKey}`;
      const findingId = `finding-${crypto.createHash("sha256").update(findingKey).digest("hex").slice(0, 16)}`;

      findings.push({
        findingId,
        tenantId,
        category: "mass_exploitation",
        title: `Mass exploitation pattern: "${unhanlded[0].title}" (${hostnames.length} hosts)`,
        severity: this.topSeverity(unhanlded),
        eventCount: unhanlded.length,
        affectedHostnames: hostnames,
        eventIds: unhanlded.map((e) => e.id),
        riskScore: this.computeRiskScore(7, false, unhanlded.length),
        evidenceIds: unhanlded.flatMap((e) => e.evidenceIds),
        correlatedAt: new Date().toISOString(),
      });

      unhanlded.forEach((e) => handled.add(e.id));
    }

    // ── 4. Lateral movement ─────────────────────────────────────────────────
    const authHosts = [...new Set(authFailures.map((e) => e.affectedAsset.hostname ?? ""))];
    if (authFailures.length >= 3 && authHosts.length >= 2) {
      const unhandled = authFailures.filter((e) => !handled.has(e.id));
      if (unhandled.length >= 3) {
        const findingKey = `lateral-movement|${tenantId}|${unhandled[0].timestamp.slice(0, 13)}`;
        const findingId = `finding-${crypto.createHash("sha256").update(findingKey).digest("hex").slice(0, 16)}`;

        findings.push({
          findingId,
          tenantId,
          category: "lateral_movement",
          title: `Potential lateral movement: auth failures across ${authHosts.length} hosts`,
          severity: "high",
          eventCount: unhandled.length,
          affectedHostnames: authHosts,
          eventIds: unhandled.map((e) => e.id),
          riskScore: 75,
          evidenceIds: unhandled.flatMap((e) => e.evidenceIds),
          correlatedAt: new Date().toISOString(),
        });

        unhandled.forEach((e) => handled.add(e.id));
      }
    }

    // ── 5. Isolated alerts (remainder) ─────────────────────────────────────
    for (const evt of events) {
      if (handled.has(evt.id)) continue;

      const findingKey = `isolated|${tenantId}|${evt.dedupFingerprint}`;
      const findingId = `finding-${crypto.createHash("sha256").update(findingKey).digest("hex").slice(0, 16)}`;

      findings.push({
        findingId,
        tenantId,
        category: "isolated_alert",
        title: evt.title,
        severity: evt.severity,
        eventCount: 1,
        affectedHostnames: [evt.affectedAsset.hostname ?? ""],
        cveId: evt.vulnerability?.cveId,
        eventIds: [evt.id],
        riskScore: this.computeRiskScore(
          evt.vulnerability?.cvssScore ?? 0,
          evt.vulnerability?.kevListed ?? false,
          1
        ),
        evidenceIds: evt.evidenceIds,
        correlatedAt: new Date().toISOString(),
      });
    }

    // Sort by risk score descending
    return findings.sort((a, b) => b.riskScore - a.riskScore);
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private static topSeverity(events: CanonicalSecurityEvent[]): CanonicalSecurityEvent["severity"] {
    const order: CanonicalSecurityEvent["severity"][] = ["critical", "high", "medium", "low", "info"];
    for (const s of order) {
      if (events.some((e) => e.severity === s)) return s;
    }
    return "info";
  }

  /**
   * Risk score formula (0–100, deterministic):
   * base = CVSS × 10
   * + 20 if KEV-listed
   * + spread bonus: min(spread × 2, 15)
   */
  private static computeRiskScore(
    cvssScore: number,
    kevListed: boolean,
    spreadCount: number
  ): number {
    const base = Math.min(100, cvssScore * 10);
    const kevBonus = kevListed ? 20 : 0;
    const spreadBonus = Math.min(spreadCount * 2, 15);
    return Math.min(100, Math.round(base + kevBonus + spreadBonus));
  }
}
