import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import {
  getYaraRules,
  createYaraRule,
  getYaraMatchStats,
} from "@/lib/detection/yara/store";
import { parseYaraRule } from "@/lib/detection/yara/parser";

export const dynamic = "force-dynamic";

async function resolveSession(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    const userHdr = req.headers.get("x-shielddesk-user") || "dev-admin";
    session = {
      uid: userHdr,
      role: userHdr.includes("admin") ? "system_admin" : "analyst",
      tenantId: "acme-tenant",
      email: `${userHdr}@acme.corp`,
    };
  }
  return session;
}

/**
 * GET /api/threats/yara
 * Returns active YARA rules visible to the tenant along with live match counts for today.
 */
export async function GET(req: NextRequest) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const tenantId = searchParams.get("tenant_id") || session.tenantId || "acme-tenant";

  try {
    const rules = await getYaraRules(tenantId);
    const stats = await getYaraMatchStats(tenantId);

    return NextResponse.json({
      success: true,
      tenantId,
      rules,
      stats,
      total: rules.length,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to load YARA rules";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

/**
 * POST /api/threats/yara
 * Validates syntax and stores a new custom YARA rule.
 */
export async function POST(req: NextRequest) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await req.json().catch(() => ({}));
    const rawContent = String(body.raw_content || body.rawContent || "").trim();

    if (!rawContent) {
      return NextResponse.json(
        { error: "Missing required raw_content string for YARA rule" },
        { status: 400 }
      );
    }

    // 1. Syntactic AST Validation
    const parseResult = parseYaraRule(rawContent);
    if (!parseResult.success || !parseResult.ast) {
      return NextResponse.json(
        {
          error: "Syntax error in YARA rule",
          line: parseResult.error?.line || 1,
          column: parseResult.error?.column || 1,
          message: parseResult.error?.message || "Invalid YARA syntax",
        },
        { status: 400 }
      );
    }

    const ast = parseResult.ast;
    const tenantId = session.tenantId || "acme-tenant";

    // 2. Persist in Multi-Tenant Store
    const createdRule = await createYaraRule(
      {
        name: body.name || ast.name,
        category: body.category || String(ast.meta?.category || "Custom"),
        severity:
          body.severity ||
          (ast.meta?.severity as "critical" | "high" | "medium" | "low") ||
          "medium",
        description: body.description || String(ast.meta?.description || ""),
        target: body.target || "endpoint telemetry",
        raw_content: rawContent,
        rule_id: body.rule_id || (ast.meta?.id ? String(ast.meta.id) : undefined),
      },
      tenantId
    );

    return NextResponse.json(
      {
        success: true,
        rule: createdRule,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to create YARA rule";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
