import { NextRequest, NextResponse } from "next/server";
import { rotateEndpointCertificate } from "@/lib/fleet/certificates";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/agent/certificate/rotate
 * Enrolled endpoint agent daemon requests a renewed X.509 certificate before expiration.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { agentId, tenantId, currentSerialNumber, newPublicKey } = body;

    if (!agentId || !currentSerialNumber || !tenantId) {
      return NextResponse.json(
        { error: "Missing required fields: agentId, tenantId, currentSerialNumber" },
        { status: 400 }
      );
    }

    const result = await rotateEndpointCertificate({
      agentId,
      tenantId,
      currentSerialNumber,
      newClientPublicKeyPem: typeof newPublicKey === "string" ? newPublicKey : undefined,
    });

    if (!result.success || !result.newCertificate) {
      return NextResponse.json({ error: result.error || "Rotation failed" }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      message: "Certificate rotated successfully",
      certificate: result.newCertificate,
    });
  } catch (err) {
    trackError(err, { route: "POST /api/agent/certificate/rotate" });
    return NextResponse.json({ error: "Failed to rotate certificate" }, { status: 500 });
  }
}
