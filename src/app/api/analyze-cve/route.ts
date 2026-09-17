import { NextRequest, NextResponse } from "next/server";
import { fetchNvdCve } from "@/lib/services/nvd";
import { summarizeCveWithGemini } from "@/lib/ai/gemini";

/**
 * GET /api/analyze-cve?cveId=CVE-2024-3400
 * POST /api/analyze-cve { "cveId": "CVE-2024-3400" }
 *
 * Pulls real CVE threat intelligence from NIST NVD API 2.0 and
 * generates a plain-English briefing, risk assessment, and mitigation plan via Gemini.
 */
async function handleAnalyze(cveIdRaw?: string | null) {
  const cveId = cveIdRaw?.trim();

  if (!cveId) {
    return NextResponse.json(
      {
        success: false,
        error: "missing_cve_id",
        message: "A CVE ID is required (e.g. CVE-2024-3400).",
      },
      { status: 400 }
    );
  }

  // Fetch real CVE data from NVD
  const nvdResult = await fetchNvdCve(cveId);

  if (!nvdResult.success || !nvdResult.record) {
    const statusMap: Record<string, number> = {
      invalid_format: 400,
      not_found: 404,
      rate_limited: 429,
    };
    const status = statusMap[nvdResult.error || ""] || 502;

    return NextResponse.json(
      {
        success: false,
        error: nvdResult.error || "fetch_failed",
        message: nvdResult.message || `Failed to retrieve data for ${cveId}.`,
      },
      { status }
    );
  }

  // Generate plain-English summary, risk, and mitigation via Gemini
  const analysis = await summarizeCveWithGemini(nvdResult.record);

  return NextResponse.json({
    success: true,
    cveId: analysis.cveId,
    severity: analysis.severity,
    cvssScore: analysis.cvssScore,
    publishedDate: analysis.publishedDate,
    summary: analysis.summary,
    risk: analysis.risk,
    mitigation: analysis.mitigation,
    analysis: analysis.analysis,
    formattedMessage: analysis.formattedMessage,
    raw: {
      description: analysis.rawDescription,
      weaknesses: nvdResult.record.weaknesses,
      references: nvdResult.record.references,
      cisaRequiredAction: nvdResult.record.cisaRequiredAction,
    },
    aiPowered: analysis.aiPowered,
  });
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const cveId = searchParams.get("cveId") || searchParams.get("id");
  return handleAnalyze(cveId);
}

export async function POST(req: NextRequest) {
  let body: { cveId?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { success: false, error: "invalid_json", message: "Invalid JSON request body." },
      { status: 400 }
    );
  }

  return handleAnalyze(body.cveId);
}
