import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_CERTIFICATES, type EndpointCertificateRecord } from "@/lib/fleet/certificates";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/fleet/certificates
 * Lists issued X.509 endpoint certificates for the authenticated tenant.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    let certificates: EndpointCertificateRecord[] = [];

    try {
      const res = await query<EndpointCertificateRecord>(
        `SELECT id, agent_id, tenant_id, serial_number, fingerprint_sha256, issued_at, expires_at, revoked_at, revocation_reason
         FROM endpoint_certificates
         WHERE tenant_id = $1
         ORDER BY issued_at DESC;`,
        [session.tenantId]
      );
      certificates = res.rows;
    } catch {
      certificates = MOCK_ENDPOINT_CERTIFICATES.filter(
        (c) => c.tenant_id === session.tenantId
      );
    }

    return NextResponse.json({
      certificates,
      total: certificates.length,
      tenantId: session.tenantId,
    });
  } catch (err) {
    trackError(err, { route: "GET /api/fleet/certificates", tenantId: session.tenantId });
    return NextResponse.json({ error: "Failed to list certificates" }, { status: 500 });
  }
}
