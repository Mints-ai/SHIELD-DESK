import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { verifyTenantLedger } from "@/lib/compliance/verifier";
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

    const verification = await verifyTenantLedger(caller);
    return NextResponse.json({
      success: true,
      verification,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance/verify" });
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

    const body = await req.json().catch(() => ({}));
    const verification = await verifyTenantLedger(caller, body.customEvents);

    return NextResponse.json({
      success: true,
      verification,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance/verify" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
