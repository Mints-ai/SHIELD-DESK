import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { LLMGateway } from "@/lib/ai/gateway";
import { EvidenceCitation } from "@/lib/ai/types";

export async function POST(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (!canAccess(session.role, "incident.investigate") && !canAccess(session.role, "incident.mitigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const body = await request.json().catch(() => ({}));
    const { incidentId, incidentTitle, untrustedTelemetry, evidenceCitations, agentIdentityId, provider, model } = body;

    if (!incidentTitle || typeof incidentTitle !== "string") {
      return NextResponse.json({ error: "Missing required string 'incidentTitle'" }, { status: 400 });
    }

    // Propose remediation plan
    if (evidenceCitations && Array.isArray(evidenceCitations)) {
      const proposal = await LLMGateway.proposeRemediation(
        incidentId || `inc-${Date.now()}`,
        incidentTitle,
        evidenceCitations as EvidenceCitation[],
        {
          tenantId: session.tenantId,
          actorId: session.uid,
          agentIdentityId,
          provider,
          model,
        }
      );
      return NextResponse.json(proposal, { status: 200 });
    }

    // Default: structured investigation
    const telemetry = Array.isArray(untrustedTelemetry) ? untrustedTelemetry : [String(incidentTitle)];
    const investigation = await LLMGateway.investigateIncident(incidentTitle, telemetry, {
      tenantId: session.tenantId,
      actorId: session.uid,
      agentIdentityId,
      provider,
      model,
    });

    return NextResponse.json(investigation, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}
