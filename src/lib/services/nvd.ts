import "server-only";

export interface NvdCveRecord {
  id: string;
  description: string;
  cvssScore: number | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  vectorString?: string;
  publishedDate: string;
  lastModifiedDate?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
  weaknesses: string[];
  references: string[];
}

export interface NvdFetchResult {
  success: boolean;
  record?: NvdCveRecord;
  error?: "invalid_format" | "not_found" | "rate_limited" | "fetch_failed" | string;
  message?: string;
}

const CVE_REGEX = /^CVE-\d{4}-\d{4,7}$/i;

/**
 * Fetch CVE vulnerability intelligence directly from the NIST National Vulnerability Database (NVD) 2.0 API.
 * Supports optional NVD_API_KEY for higher rate limits (50 req/30s vs 5 req/30s).
 */
export async function fetchNvdCve(cveId: string): Promise<NvdFetchResult> {
  const normalizedId = cveId.trim().toUpperCase();

  if (!CVE_REGEX.test(normalizedId)) {
    return {
      success: false,
      error: "invalid_format",
      message: `Invalid CVE ID format: "${cveId}". Expected format: CVE-YYYY-NNNNN (e.g. CVE-2024-3400).`,
    };
  }

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(normalizedId)}`;

  const headers: Record<string, string> = {
    "User-Agent": "ShieldDesk-CyberSecurity/1.0",
    Accept: "application/json",
  };

  const apiKey = process.env.NVD_API_KEY?.trim();
  if (apiKey) {
    headers["apiKey"] = apiKey;
  }

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(12000),
      // Cache for 1 hour to optimize performance and prevent rate limiting
      next: { revalidate: 3600 },
    });

    if (res.status === 404) {
      return {
        success: false,
        error: "not_found",
        message: `No vulnerability details found in NVD for ${normalizedId}.`,
      };
    }

    if (res.status === 403 || res.status === 429) {
      return {
        success: false,
        error: "rate_limited",
        message: "NVD API rate limit reached. Please wait a moment or configure an NVD_API_KEY.",
      };
    }

    if (!res.ok) {
      return {
        success: false,
        error: "fetch_failed",
        message: `NVD API responded with status ${res.status}.`,
      };
    }

    const data = await res.json();
    const vulnerabilities = data?.vulnerabilities;

    if (!vulnerabilities || !Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
      return {
        success: false,
        error: "not_found",
        message: `CVE ${normalizedId} was not found in the NVD database.`,
      };
    }

    const cve = vulnerabilities[0]?.cve;
    if (!cve) {
      return {
        success: false,
        error: "not_found",
        message: `No CVE record details found for ${normalizedId}.`,
      };
    }

    // Extract English description
    const descObj =
      cve.descriptions?.find((d: { lang?: string }) => d.lang === "en") ||
      cve.descriptions?.[0];
    const description = descObj?.value || "No description provided by NVD.";

    // Extract CVSS metric (prefer v3.1, then v3.0, then v2.0)
    let cvssScore: number | null = null;
    let severity: NvdCveRecord["severity"] = "UNKNOWN";
    let vectorString: string | undefined = undefined;

    const v31 = cve.metrics?.cvssMetricV31;
    const v30 = cve.metrics?.cvssMetricV30;
    const v20 = cve.metrics?.cvssMetricV2;

    const preferredV3 = Array.isArray(v31) && v31.length > 0 ? v31[0] : Array.isArray(v30) && v30.length > 0 ? v30[0] : null;

    if (preferredV3?.cvssData) {
      cvssScore = typeof preferredV3.cvssData.baseScore === "number" ? preferredV3.cvssData.baseScore : null;
      vectorString = preferredV3.cvssData.vectorString;
      const rawSev = (preferredV3.cvssData.baseSeverity || preferredV3.baseSeverity || "").toUpperCase();
      if (rawSev === "CRITICAL" || rawSev === "HIGH" || rawSev === "MEDIUM" || rawSev === "LOW") {
        severity = rawSev;
      }
    } else if (Array.isArray(v20) && v20.length > 0 && v20[0]?.cvssData) {
      const metric = v20[0];
      cvssScore = typeof metric.cvssData.baseScore === "number" ? metric.cvssData.baseScore : null;
      vectorString = metric.cvssData.vectorString;
      const rawSev = (metric.baseSeverity || "").toUpperCase();
      if (rawSev === "HIGH" || rawSev === "MEDIUM" || rawSev === "LOW") {
        severity = rawSev;
      }
    }

    // Extract weaknesses (CWEs)
    const weaknesses: string[] = [];
    if (Array.isArray(cve.weaknesses)) {
      for (const w of cve.weaknesses) {
        if (Array.isArray(w.description)) {
          for (const d of w.description) {
            if (d.value && typeof d.value === "string" && !weaknesses.includes(d.value)) {
              weaknesses.push(d.value);
            }
          }
        }
      }
    }

    // Extract references
    const references: string[] = [];
    if (Array.isArray(cve.references)) {
      for (const r of cve.references) {
        if (r.url && typeof r.url === "string" && references.length < 5) {
          references.push(r.url);
        }
      }
    }

    const record: NvdCveRecord = {
      id: cve.id || normalizedId,
      description,
      cvssScore,
      severity,
      vectorString,
      publishedDate: cve.published || new Date().toISOString(),
      lastModifiedDate: cve.lastModified,
      cisaRequiredAction: cve.cisaRequiredAction,
      cisaVulnerabilityName: cve.cisaVulnerabilityName,
      weaknesses,
      references,
    };

    return {
      success: true,
      record,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      error: "fetch_failed",
      message: `Failed to fetch data from NVD: ${message}`,
    };
  }
}
