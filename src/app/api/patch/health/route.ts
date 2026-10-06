import { NextResponse } from "next/server";

const ORCHESTRATOR_URL = process.env.PATCH_ORCHESTRATOR_URL || "http://localhost:8004";

export async function GET() {
  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/health`, {
      signal: AbortSignal.timeout(2000),
    });
    if (res.ok) {
      const data = await res.json();
      return NextResponse.json({ online: true, ...data });
    }
    return NextResponse.json({ online: false }, { status: 503 });
  } catch {
    return NextResponse.json({ online: false }, { status: 503 });
  }
}
