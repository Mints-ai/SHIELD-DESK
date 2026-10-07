import { NextRequest, NextResponse } from "next/server";
import { parseYaraRule } from "@/lib/detection/yara/parser";
import { evaluateYaraRule } from "@/lib/detection/yara/evaluator";
import { getYaraRuleById } from "@/lib/detection/yara/store";

export const dynamic = "force-dynamic";

/**
 * POST /api/threats/yara/test
 * Ad-hoc sandbox evaluation endpoint for testing candidate rules against payload samples.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    let rawContent = String(body.raw_content || body.rawContent || "").trim();
    const ruleId = body.rule_id || body.ruleId;
    const samplePayload = body.sample_payload ?? body.samplePayload ?? body.payload ?? "";
    const isBase64 = Boolean(body.is_base64 || body.isBase64);

    // If rule_id provided without raw_content, look up existing rule
    if (!rawContent && ruleId) {
      const existing = await getYaraRuleById(String(ruleId));
      if (existing) {
        rawContent = existing.raw_content;
      }
    }

    if (!rawContent) {
      return NextResponse.json(
        { error: "Must provide either raw_content or a valid rule_id to test" },
        { status: 400 }
      );
    }

    // 1. Validate Syntax
    const parseRes = parseYaraRule(rawContent);
    if (!parseRes.success || !parseRes.ast) {
      return NextResponse.json(
        {
          error: "Syntax error in candidate YARA rule",
          line: parseRes.error?.line || 1,
          column: parseRes.error?.column || 1,
          message: parseRes.error?.message || "Invalid syntax",
        },
        { status: 400 }
      );
    }

    // 2. Prepare Payload
    let payloadToScan: string | Buffer = String(samplePayload);
    if (isBase64 && typeof samplePayload === "string") {
      try {
        payloadToScan = Buffer.from(samplePayload, "base64");
      } catch {
        payloadToScan = String(samplePayload);
      }
    }

    // 3. Dry-Run Evaluation with strict 50ms safety timeout
    const evalRes = evaluateYaraRule(parseRes.ast, payloadToScan, { timeoutMs: 50 });

    return NextResponse.json({
      success: true,
      matched: evalRes.matched,
      ruleName: evalRes.ruleName,
      ruleId: evalRes.ruleId,
      category: evalRes.category,
      severity: evalRes.severity,
      matches: evalRes.matches,
      matchesCount: evalRes.matches.length,
      executionTimeMs: evalRes.executionTimeMs,
      error: evalRes.error,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Error testing YARA rule";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
