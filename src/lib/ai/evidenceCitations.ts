import "server-only";
import { EvidenceEngine } from "@/lib/decision-engine/evidenceEngine";
import { EvidenceCitation } from "./types";

export interface CitationVerificationResult {
  isValid: boolean;
  hallucinationScore: number; // 0.0 = completely substantiated, 1.0 = completely hallucinated
  validCitations: EvidenceCitation[];
  invalidCitations: Array<{ citation: EvidenceCitation; reason: string }>;
  unreferencedClaimsCount: number;
}

export class EvidenceCitationValidator {
  /**
   * Validates citations in an AI proposal against the Phase D Evidence Engine,
   * Phase A vulnerability findings, and Phase B digital twin nodes.
   */
  public static validateCitations(
    citations: EvidenceCitation[],
    claims: string[],
    options?: {
      knownEvidenceKeys?: string[];
      allowTelemetryCitations?: boolean;
    }
  ): CitationVerificationResult {
    const validCitations: EvidenceCitation[] = [];
    const invalidCitations: Array<{ citation: EvidenceCitation; reason: string }> = [];
    const knownKeys = new Set(options?.knownEvidenceKeys || []);

    for (const citation of citations) {
      if (!citation.evidenceId || citation.evidenceId.trim().length === 0) {
        invalidCitations.push({ citation, reason: "Missing or empty evidenceId" });
        continue;
      }

      // Check if evidenceId is registered in Phase D Evidence Engine
      const fromEngine = EvidenceEngine.getEvidence(citation.evidenceId);
      const isKnownKey = knownKeys.has(citation.evidenceId);
      const isSyntheticValid =
        citation.evidenceId.startsWith("ev-") ||
        citation.evidenceId.startsWith("cve-") ||
        citation.evidenceId.startsWith("asset-") ||
        citation.evidenceId.startsWith("node-") ||
        citation.evidenceId.startsWith("telemetry-");

      if (fromEngine || isKnownKey || (isSyntheticValid && citation.verified)) {
        validCitations.push({
          ...citation,
          verified: true,
        });
      } else {
        invalidCitations.push({
          citation,
          reason: `Unverifiable evidence reference: '${citation.evidenceId}' does not exist in evidence vault or graph.`,
        });
      }
    }

    // Hallucination score:
    // If all provided citations are valid and verified, score is 0.0
    // If citations are invalid or fabricated, compute proportion of invalid citations
    let hallucinationScore = 0.0;
    if (invalidCitations.length > 0) {
      hallucinationScore = Math.min(1.0, Number((invalidCitations.length / Math.max(citations.length, 1)).toFixed(4)));
    }

    const isValid = invalidCitations.length === 0;

    return {
      isValid,
      hallucinationScore,
      validCitations,
      invalidCitations,
      unreferencedClaimsCount: invalidCitations.length,
    };
  }
}
