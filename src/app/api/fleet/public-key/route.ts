import { NextResponse } from "next/server";
import { getControlPlanePublicKey } from "@/lib/fleet/commandSigning";

/**
 * GET /api/fleet/public-key
 * Returns the control plane's RSA-2048 public key in PEM format
 * for remote endpoint agents to verify command signatures.
 */
export async function GET() {
  const publicKey = getControlPlanePublicKey();
  return NextResponse.json({
    publicKey,
    algorithm: "RSA-SHA256",
    keySize: 2048,
  });
}
