import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { getIncidents, investigateIncident } from "@/lib/tools";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(req.url);
    const incidentId = searchParams.get("id");
    const severity = searchParams.get("severity") || undefined;
    const status = searchParams.get("status") || undefined;

    if (incidentId) {
      const result = await investigateIncident(session, { incidentId });
      if ("error" in result) {
        const statusCode = result.error === "not_found" ? 404 : 400;
        return NextResponse.json(result, { status: statusCode });
      }
      return NextResponse.json(result);
    }

    const result = await getIncidents(session, { severity, status, limit: 20 });
    return NextResponse.json(result);
  } catch (err) {
    trackError(err, {
      endpoint: "/api/incidents",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json({ error: "Failed to retrieve incidents" }, { status: 500 });
  }
}

