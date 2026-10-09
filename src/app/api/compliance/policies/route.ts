import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import {
  listCompliancePolicies,
  createOrUpdatePolicy,
} from "@/lib/compliance/policyStore";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const policies = await listCompliancePolicies(caller);
    return NextResponse.json({
      success: true,
      policies,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance/policies" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const body = await req.json();
    if (!body.policyCode || !body.title || !body.category) {
      return NextResponse.json(
        { error: "Missing required fields: policyCode, title, category" },
        { status: 400 }
      );
    }

    const created = await createOrUpdatePolicy(caller, {
      policyCode: body.policyCode,
      title: body.title,
      category: body.category,
      description: body.description || "",
      version: body.version || "1.0",
      controlMappings: Array.isArray(body.controlMappings) ? body.controlMappings : [],
      documentUrl: body.documentUrl,
    });

    return NextResponse.json(
      {
        success: true,
        policy: created,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance/policies" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
