import { NextResponse } from "next/server";
import { getRootCACertificatePem } from "@/lib/fleet/certificates";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/fleet/ca
 * Returns the ShieldDesk Root CA certificate PEM for endpoint daemons to verify control plane TLS.
 */
export async function GET() {
  try {
    const caCertificatePem = getRootCACertificatePem();
    return NextResponse.json({
      caCertificate: caCertificatePem,
      subject: "CN=ShieldDesk Root CA, O=ShieldDesk Control Plane, OU=Security Services",
      algorithm: "sha256WithRSAEncryption",
      keySize: 2048,
    });
  } catch (err) {
    trackError(err, { route: "GET /api/fleet/ca" });
    return NextResponse.json({ error: "Failed to load CA certificate" }, { status: 500 });
  }
}
