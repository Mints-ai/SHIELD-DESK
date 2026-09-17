import "server-only";
import type { NvdCveRecord } from "@/lib/services/nvd";

export interface CveAnalysisResult {
  cveId: string;
  severity: string;
  cvssScore: number | null;
  publishedDate: string;
  rawDescription: string;
  summary: string;
  risk: string;
  mitigation: string;
  analysis: string;
  formattedMessage: string;
  aiPowered: boolean;
}

const DEFAULT_GEMINI_MODEL = "gemini-2.0-flash";

/**
 * Sends NVD CVE threat intelligence data to Google Gemini to generate a plain-English
 * summary, risk explanation, and suggested mitigation.
 * If GEMINI_API_KEY is not configured or offline, gracefully falls back to structured NVD data.
 */
export async function summarizeCveWithGemini(record: NvdCveRecord): Promise<CveAnalysisResult> {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  const model = process.env.GEMINI_MODEL?.trim() || DEFAULT_GEMINI_MODEL;

  const cvssDisplay = record.cvssScore !== null ? `${record.cvssScore} (${record.severity})` : record.severity;

  if (apiKey) {
    try {
      const prompt = `You are a cybersecurity expert analyzing a vulnerability for an incident response and SOC team.
Here is the raw CVE threat intelligence data from the National Vulnerability Database (NVD):

CVE ID: ${record.id}
Published Date: ${record.publishedDate}
CVSS Base Score: ${cvssDisplay}
Vector: ${record.vectorString || "N/A"}
CWE Weaknesses: ${record.weaknesses.length > 0 ? record.weaknesses.join(", ") : "N/A"}
CISA Known Exploited Status: ${record.cisaRequiredAction ? `Active (Action: ${record.cisaRequiredAction})` : "Not listed in CISA KEV"}

Raw NVD Description:
${record.description}

Please provide a plain-language briefing structured as follows:
SUMMARY: A clear, plain-language explanation of what this vulnerability is and what component is vulnerable.
RISK: The real-world impact, attack scenario, and danger to an organization if exploited.
MITIGATION: Recommended concrete fix, patch guidance, or workaround.

Keep each section direct, concise, and focused on practical defense.`;

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [
              {
                parts: [{ text: prompt }],
              },
            ],
            generationConfig: {
              temperature: 0.2,
              maxOutputTokens: 1000,
            },
          }),
          signal: AbortSignal.timeout(15000),
        }
      );

      if (response.ok) {
        const json = await response.json();
        const candidateText = json?.candidates?.[0]?.content?.parts?.[0]?.text;

        if (candidateText && typeof candidateText === "string") {
          const { summary, risk, mitigation } = parseSections(candidateText, record);
          const formattedMessage = buildFormattedReply({
            cveId: record.id,
            severity: record.severity,
            cvssScore: record.cvssScore,
            summary,
            risk,
            mitigation,
          });

          return {
            cveId: record.id,
            severity: record.severity,
            cvssScore: record.cvssScore,
            publishedDate: record.publishedDate,
            rawDescription: record.description,
            summary,
            risk,
            mitigation,
            analysis: candidateText.trim(),
            formattedMessage,
            aiPowered: true,
          };
        }
      } else {
        console.warn(`Gemini API returned status ${response.status}:`, await response.text().catch(() => ""));
      }
    } catch (err) {
      console.warn("Gemini API call failed, falling back to structured NVD data:", err);
    }
  }

  // Fallback if GEMINI_API_KEY is not configured or call fails:
  const fallbackSummary = record.description;
  const fallbackRisk = record.cvssScore && record.cvssScore >= 9.0
    ? "Critical risk of remote compromise or arbitrary code execution with maximum operational impact."
    : record.cvssScore && record.cvssScore >= 7.0
    ? "High risk vulnerability requiring immediate patching to prevent unauthorized access or system disruption."
    : "Moderate risk vulnerability requiring scheduled patching and monitoring.";

  const fallbackMitigation = record.cisaRequiredAction
    ? record.cisaRequiredAction
    : `Apply vendor patches for ${record.id}, isolate affected assets, and monitor perimeter firewalls.`;

  const fallbackFormatted = buildFormattedReply({
    cveId: record.id,
    severity: record.severity,
    cvssScore: record.cvssScore,
    summary: fallbackSummary,
    risk: fallbackRisk,
    mitigation: fallbackMitigation,
    note: !apiKey ? "Tip: Configure GEMINI_API_KEY in .env.local for AI-generated plain language synthesis." : undefined,
  });

  return {
    cveId: record.id,
    severity: record.severity,
    cvssScore: record.cvssScore,
    publishedDate: record.publishedDate,
    rawDescription: record.description,
    summary: fallbackSummary,
    risk: fallbackRisk,
    mitigation: fallbackMitigation,
    analysis: `${fallbackSummary}\n\nRisk: ${fallbackRisk}\n\nMitigation: ${fallbackMitigation}`,
    formattedMessage: fallbackFormatted,
    aiPowered: false,
  };
}

/**
 * Extracts SUMMARY, RISK, and MITIGATION sections from Gemini's response text.
 */
function parseSections(text: string, record: NvdCveRecord) {
  const summaryMatch = text.match(/SUMMARY:\s*([\s\S]*?)(?=(RISK:|MITIGATION:|$))/i);
  const riskMatch = text.match(/RISK:\s*([\s\S]*?)(?=(SUMMARY:|MITIGATION:|$))/i);
  const mitigationMatch = text.match(/MITIGATION:\s*([\s\S]*?)(?=(SUMMARY:|RISK:|$))/i);

  const summary = summaryMatch?.[1]?.trim() || record.description;
  const risk = riskMatch?.[1]?.trim() || (record.severity === "CRITICAL" ? "Severe threat of unauthorized access or code execution." : "Potential threat to system integrity.");
  const mitigation = mitigationMatch?.[1]?.trim() || record.cisaRequiredAction || "Apply vendor patches and restrict network exposure.";

  return { summary, risk, mitigation };
}

/**
 * Formats a clean, readable message suitable for the chat interface.
 */
function buildFormattedReply(data: {
  cveId: string;
  severity: string;
  cvssScore: number | null;
  summary: string;
  risk: string;
  mitigation: string;
  note?: string;
}): string {
  const scoreStr = data.cvssScore !== null ? ` (CVSS ${data.cvssScore})` : "";
  const lines = [
    `CVE ID: ${data.cveId}`,
    `Severity: ${data.severity}${scoreStr}`,
    `Summary: ${data.summary}`,
    `Risk: ${data.risk}`,
    `Suggested Fix: ${data.mitigation}`,
  ];

  if (data.note) {
    lines.push(`\n[${data.note}]`);
  }

  return lines.join("\n\n");
}
