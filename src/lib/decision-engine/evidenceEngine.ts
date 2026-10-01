import crypto from "node:crypto";
import { DecisionEvidenceItem, ExplainableRiskFactor } from "./types";
import { RiskSeverity } from "../policy-engine/types";

export interface ExplainableRiskInput {
  tenantId: string;
  cve?: {
    cveId?: string;
    cvss?: number;
    epss?: number;
    kev?: boolean;
  };
  asset?: {
    id?: string;
    criticality?: "low" | "medium" | "high" | "critical";
    internetFacing?: boolean;
    isChokePoint?: boolean;
    storesPiiOrPci?: boolean;
  };
  blastRadius?: {
    score?: number;
    calculationMode?: "measured" | "inferred" | "simulated" | "estimated";
  };
  evidence: DecisionEvidenceItem[];
}

export interface ExplainableRiskResult {
  score: number; // 0.0 to 10.0
  severity: RiskSeverity;
  factors: ExplainableRiskFactor[];
  evidenceIds: string[];
  securityConfidence: number; // 0.0 to 1.0 deterministic confidence
  summary: string;
}

export class EvidenceEngine {
  private static evidenceRegistry: Map<string, DecisionEvidenceItem> = new Map();

  /**
   * Stores an evidence item in the registry.
   */
  public static storeEvidence(item: DecisionEvidenceItem): void {
    if (item.id) {
      this.evidenceRegistry.set(item.id, item);
    }
  }

  /**
   * Retrieves an evidence item by ID.
   */
  public static getEvidence(id: string): DecisionEvidenceItem | undefined {
    return this.evidenceRegistry.get(id);
  }

  /**
   * Constructs a canonical, tamper-evident DecisionEvidenceItem with deterministic SHA-256 hash.
   */
  public static createEvidence(
    type: string,
    source: string,
    data: Record<string, unknown>,
    timestamp?: string
  ): DecisionEvidenceItem {
    const ts = timestamp || new Date().toISOString();
    const canonicalPayload = JSON.stringify({ type, source, data, timestamp: ts });
    const hash = crypto.createHash("sha256").update(canonicalPayload).digest("hex");
    const id = `evi-${hash.slice(0, 16)}`;

    const item: DecisionEvidenceItem = {
      id,
      type,
      source,
      timestamp: ts,
      data,
      hash,
    };
    this.storeEvidence(item);
    return item;
  }

  /**
   * Verifies the cryptographic hash integrity of an evidence item.
   */
  public static verifyEvidenceIntegrity(item: DecisionEvidenceItem): boolean {
    if (!item.hash) return false;
    const canonicalPayload = JSON.stringify({
      type: item.type,
      source: item.source,
      data: item.data,
      timestamp: item.timestamp,
    });
    const expectedHash = crypto.createHash("sha256").update(canonicalPayload).digest("hex");
    return item.hash === expectedHash;
  }

  /**
   * Evaluates explainable risk where EVERY risk factor carries an explicit evidence reference.
   * Deterministically calculates both risk score and security confidence.
   */
  public static calculateExplainableRisk(input: ExplainableRiskInput): ExplainableRiskResult {
    const factors: ExplainableRiskFactor[] = [];
    const evidenceList = [...input.evidence];

    // Helper to find or synthesize an evidence item for a factor
    const resolveEvidenceId = (
      type: string,
      source: string,
      data: Record<string, unknown>
    ): string => {
      const existing = evidenceList.find((e) => e.type === type);
      if (existing && existing.id) return existing.id;
      const created = this.createEvidence(type, source, data);
      evidenceList.push(created);
      return created.id!;
    };

    let runningScore = 2.0; // Baseline ambient threat score

    // 1. CVSS Base Factor
    if (input.cve && typeof input.cve.cvss === "number") {
      const cvss = input.cve.cvss;
      const delta = Number((cvss * 0.4).toFixed(2));
      runningScore += delta;
      const eviId = resolveEvidenceId("cve_cvss_score", "nvd_vuln_intelligence", {
        cveId: input.cve.cveId || "CVE-UNKNOWN",
        cvss,
      });
      factors.push({
        factor: "CVSS Severity Impact",
        scoreDelta: delta,
        weight: 0.4,
        evidenceId: eviId,
        evidenceType: "cve_cvss_score",
        description: `Base vulnerability severity CVSS ${cvss}/10 recorded for ${input.cve.cveId || "target vulnerability"}.`,
      });
    }

    // 2. CISA KEV (Known Exploited Vulnerabilities) Factor
    if (input.cve?.kev) {
      const delta = 2.0;
      runningScore += delta;
      const eviId = resolveEvidenceId("cisa_kev_active_exploit", "cisa_kev_catalog", {
        cveId: input.cve.cveId,
        inTheWild: true,
      });
      factors.push({
        factor: "CISA KEV In-the-Wild Exploitation",
        scoreDelta: delta,
        weight: 0.2,
        evidenceId: eviId,
        evidenceType: "cisa_kev_active_exploit",
        description: `CVE ${input.cve.cveId} is actively weaponized and confirmed in CISA KEV catalog.`,
      });
    }

    // 3. EPSS (Exploit Prediction Scoring System) Factor
    if (input.cve && typeof input.cve.epss === "number" && input.cve.epss > 0.2) {
      const delta = Number((input.cve.epss * 2.0).toFixed(2));
      runningScore += delta;
      const eviId = resolveEvidenceId("first_epss_probability", "epss_feed", {
        cveId: input.cve.cveId,
        epssProbability: input.cve.epss,
      });
      factors.push({
        factor: "EPSS High Exploit Probability",
        scoreDelta: delta,
        weight: 0.15,
        evidenceId: eviId,
        evidenceType: "first_epss_probability",
        description: `EPSS predictive probability of ${Math.round(input.cve.epss * 100)}% indicates imminent mass exploitation.`,
      });
    }

    // 4. Asset Criticality Factor
    if (input.asset?.criticality === "critical" || input.asset?.criticality === "high") {
      const isCrit = input.asset.criticality === "critical";
      const delta = isCrit ? 1.5 : 1.0;
      runningScore += delta;
      const eviId = resolveEvidenceId("asset_inventory_criticality", "cmdb_asset_service", {
        assetId: input.asset.id,
        criticality: input.asset.criticality,
      });
      factors.push({
        factor: "Asset Criticality Weighting",
        scoreDelta: delta,
        weight: 0.15,
        evidenceId: eviId,
        evidenceType: "asset_inventory_criticality",
        description: `Target asset designated as ${input.asset.criticality.toUpperCase()} tier infrastructure.`,
      });
    }

    // 5. Perimeter Exposure (Internet-facing / DMZ) Factor
    if (input.asset?.internetFacing) {
      const delta = 1.0;
      runningScore += delta;
      const eviId = resolveEvidenceId("network_topology_exposure", "security_digital_twin", {
        assetId: input.asset.id,
        internetFacing: true,
      });
      factors.push({
        factor: "Perimeter Exposure (Internet-Facing)",
        scoreDelta: delta,
        weight: 0.1,
        evidenceId: eviId,
        evidenceType: "network_topology_exposure",
        description: "Target asset is accessible from public untrusted ingress networks.",
      });
    }

    // 6. Choke-Point Amplification Factor
    if (input.asset?.isChokePoint) {
      const delta = 1.0;
      runningScore += delta;
      const eviId = resolveEvidenceId("attack_path_choke_point", "attack_path_engine", {
        assetId: input.asset.id,
        isChokePoint: true,
      });
      factors.push({
        factor: "Critical Kill-Chain Choke Point",
        scoreDelta: delta,
        weight: 0.1,
        evidenceId: eviId,
        evidenceType: "attack_path_choke_point",
        description: "Asset constitutes a critical choke point traversing multiple viable attack paths.",
      });
    }

    // 7. Data Sensitivity (PII / PCI / HIPAA / SOX) Factor
    if (input.asset?.storesPiiOrPci) {
      const delta = 1.0;
      runningScore += delta;
      const eviId = resolveEvidenceId("data_classification_compliance", "compliance_vault", {
        assetId: input.asset.id,
        regulatedData: true,
      });
      factors.push({
        factor: "Regulated Sensitive Data Impact",
        scoreDelta: delta,
        weight: 0.1,
        evidenceId: eviId,
        evidenceType: "data_classification_compliance",
        description: "Asset holds or processes regulated customer data subject to compliance controls.",
      });
    }

    // Bound final score between 0.0 and 10.0
    const finalScore = Number(Math.min(10.0, Math.max(0.5, runningScore)).toFixed(1));

    // Determine severity
    let severity: RiskSeverity = "low";
    if (finalScore >= 8.5) severity = "critical";
    else if (finalScore >= 7.0) severity = "high";
    else if (finalScore >= 4.0) severity = "medium";

    // Deterministic Security Confidence calculation
    let confidence = 0.95;
    if (input.evidence.length === 0) {
      confidence = 0.35; // Rule: Zero prior evidence heavily penalizes confidence
    } else if (input.evidence.length < 3) {
      confidence -= 0.15;
    }

    if (input.blastRadius?.calculationMode === "estimated") {
      confidence -= 0.25;
    } else if (input.blastRadius?.calculationMode === "simulated") {
      confidence -= 0.1;
    }

    if (!input.cve?.cvss) {
      confidence -= 0.1;
    }

    const securityConfidence = Number(Math.min(1.0, Math.max(0.2, confidence)).toFixed(2));

    const evidenceIds = Array.from(new Set(factors.map((f) => f.evidenceId)));
    const summary = `Evaluated risk score ${finalScore}/10 (${severity.toUpperCase()}) across ${factors.length} evidence-backed factors. Security confidence: ${Math.round(securityConfidence * 100)}%.`;

    return {
      score: finalScore,
      severity,
      factors,
      evidenceIds,
      securityConfidence,
      summary,
    };
  }
}
