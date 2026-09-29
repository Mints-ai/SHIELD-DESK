import { NextResponse } from "next/server";
import { getControlPlanePublicKey } from "@/lib/fleet/commandSigning";

/**
 * GET /api/agent/public-key
 * Alias endpoint for enrolled agents to retrieve the control plane RSA-2048 public key.
 */
export async function GET() {
  const publicKey = getControlPlanePublicKey();
  return NextResponse.json({
    publicKey,
    algorithm: "RSA-SHA256",
    keySize: 2048,
  });
}
