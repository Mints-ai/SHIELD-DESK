import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getExecutiveRiskScorecard } from "@/lib/reporting/scorecard";

export async function GET(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    const scorecard = await getExecutiveRiskScorecard(caller);
    return NextResponse.json(scorecard);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
