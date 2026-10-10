import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";

export async function GET(req: NextRequest) {
  try {
    const session = await getSessionFromRequest(req);
    const tenantId = session?.tenantId;
    if (!tenantId) {
      return NextResponse.json({ error: "Authentication required." }, { status: 401 });
    }

    const activations = await LicenseActivationService.listActivations(tenantId);
    return NextResponse.json({ success: true, tenantId, activations });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to list activations.";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
