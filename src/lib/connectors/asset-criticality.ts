/**
 * ShieldDesk Phase A — Asset Criticality Service
 *
 * Enriches normalized security events with asset criticality profiles and
 * business impact classifications. This is the single authoritative source
 * of asset criticality for the attack-path and blast-radius engines.
 *
 * Design:
 * - In-memory criticality registry per tenant (populated from DB at startup).
 * - Deterministic rule-based assignment from asset hostname / tag patterns.
 * - Business impact mapping: revenue-generating, compliance-critical, operational, reputational.
 * - Criticality drives blast-radius thresholds and approval tier escalation.
 */

import type { AssetCriticality, AssetCriticalityProfile, BusinessImpact, CanonicalSecurityEvent } from "./event-model";

// ──────────────────────────────────────────────────────────────────────────────
// Criticality Rule
// ──────────────────────────────────────────────────────────────────────────────

interface CriticalityRule {
  /** Regex tested against hostname (case-insensitive) */
  hostnamePattern?: RegExp;
  /** Required tag (case-insensitive) */
  tag?: string;
  criticality: AssetCriticality;
  businessImpact: BusinessImpact;
  justification: string;
}

// Default rule table — ordered by priority (first match wins)
const DEFAULT_RULES: CriticalityRule[] = [
  {
    // Matches: dc01, dc-prod, dc.corp, domain-controller-01, ad-srv, ldap-01
    hostnamePattern: /(?:^|[-._])dc\d*(?:[-._]|$)|\b(domain-controller|ldap)\b/i,
    criticality: "critical",
    businessImpact: "compliance",
    justification: "Active Directory domain controllers are highest-criticality: compromise = tenant-wide breach",
  },
  {
    hostnamePattern: /\b(pay|payment|billing|stripe|razorpay|fin|finance)\b/i,
    criticality: "critical",
    businessImpact: "revenue",
    justification: "Payment processing infrastructure: breach incurs PCI-DSS liability and direct revenue loss",
  },
  {
    hostnamePattern: /\b(db|database|postgres|mysql|mongo|elastic|redis|sql)\b/i,
    criticality: "critical",
    businessImpact: "compliance",
    justification: "Database servers: contain PII or sensitive records with regulatory obligations",
  },
  {
    hostnamePattern: /\b(siem|wazuh|splunk|log|security|soc|ids|ips)\b/i,
    criticality: "critical",
    businessImpact: "operational",
    justification: "Security monitoring infrastructure: tampering undermines all security controls",
  },
  {
    hostnamePattern: /\b(api|gateway|backend|srv|service|app)\b/i,
    criticality: "high",
    businessImpact: "operational",
    justification: "Application servers: outage or compromise degrades service delivery",
  },
  {
    hostnamePattern: /\b(mail|exchange|smtp|pop3|imap)\b/i,
    criticality: "high",
    businessImpact: "reputational",
    justification: "Email infrastructure: compromise enables phishing campaigns against customers",
  },
  {
    hostnamePattern: /\b(jump|bastion|vpn|proxy|fw|firewall)\b/i,
    criticality: "high",
    businessImpact: "operational",
    justification: "Network boundary devices: compromise provides lateral movement entry",
  },
  {
    hostnamePattern: /\b(ci|jenkins|github|gitlab|deploy|build|cd)\b/i,
    criticality: "high",
    businessImpact: "operational",
    justification: "CI/CD systems: supply chain attack vector — can inject malicious builds",
  },
  {
    hostnamePattern: /\b(web|www|nginx|apache|iis|cdn)\b/i,
    criticality: "medium",
    businessImpact: "reputational",
    justification: "Web servers: defacement or data leak causes reputational damage",
  },
  {
    hostnamePattern: /\b(ws|workstation|laptop|desktop|pc|client)\b/i,
    criticality: "medium",
    businessImpact: "operational",
    justification: "User endpoints: compromise risks lateral movement and data exfiltration",
  },
];

const DEFAULT_PROFILE: AssetCriticalityProfile = {
  criticality: "low",
  businessImpact: "low",
  justification: "No matching criticality rule — assigned default low criticality",
};

// ──────────────────────────────────────────────────────────────────────────────
// Service
// ──────────────────────────────────────────────────────────────────────────────

export class AssetCriticalityService {
  /**
   * Per-tenant override registry: { tenantId → { hostname → profile } }
   * Populated from DB or via registerOverride() for tenant-specific rules.
   */
  private static overrides: Map<string, Map<string, AssetCriticalityProfile>> = new Map();

  /**
   * Classify an asset's criticality from hostname and optional tags.
   * Order: tenant override → default rule table → default profile.
   */
  static classify(
    tenantId: string,
    hostname: string,
    tags: string[] = []
  ): AssetCriticalityProfile {
    const lcHostname = hostname.toLowerCase();

    // 1. Tenant-specific override (exact hostname match)
    const tenantOverrides = this.overrides.get(tenantId);
    if (tenantOverrides) {
      const override = tenantOverrides.get(lcHostname);
      if (override) return override;
    }

    // 2. Default rule table
    for (const rule of DEFAULT_RULES) {
      const hostnameMatch = rule.hostnamePattern ? rule.hostnamePattern.test(lcHostname) : true;
      const tagMatch = rule.tag
        ? tags.some((t) => t.toLowerCase() === rule.tag!.toLowerCase())
        : true;
      if (hostnameMatch && tagMatch) {
        return {
          criticality: rule.criticality,
          businessImpact: rule.businessImpact,
          justification: rule.justification,
        };
      }
    }

    return DEFAULT_PROFILE;
  }

  /**
   * Enrich a CanonicalSecurityEvent in-place with criticality data.
   * Returns the enriched event (same object reference).
   */
  static enrich(event: CanonicalSecurityEvent): CanonicalSecurityEvent {
    const hostname = event.affectedAsset.hostname ?? "";
    const profile = this.classify(event.tenantId, hostname, event.tags);
    event.affectedAsset.criticality = profile.criticality;
    event.affectedAsset.businessImpact = profile.businessImpact;
    return event;
  }

  /**
   * Register a tenant-specific criticality override for a hostname.
   * Tenant admins can set this via the fleet management API.
   */
  static registerOverride(
    tenantId: string,
    hostname: string,
    criticality: AssetCriticality,
    businessImpact: BusinessImpact,
    justification: string
  ): void {
    if (!this.overrides.has(tenantId)) {
      this.overrides.set(tenantId, new Map());
    }
    this.overrides.get(tenantId)!.set(hostname.toLowerCase(), {
      criticality,
      businessImpact,
      justification,
    });
  }

  /**
   * Bulk load tenant overrides (e.g. from DB at startup).
   */
  static loadOverrides(
    tenantId: string,
    entries: Array<{
      hostname: string;
      criticality: AssetCriticality;
      businessImpact: BusinessImpact;
      justification: string;
    }>
  ): void {
    for (const e of entries) {
      this.registerOverride(
        tenantId,
        e.hostname,
        e.criticality,
        e.businessImpact,
        e.justification
      );
    }
  }

  /** Clear all overrides (used in tests) */
  static clearOverrides(tenantId?: string): void {
    if (tenantId) {
      this.overrides.delete(tenantId);
    } else {
      this.overrides.clear();
    }
  }
}
