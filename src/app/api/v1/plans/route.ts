import { NextResponse } from "next/server";
import { getPublicCatalog } from "@/lib/billing/catalog";

/**
 * GET /api/v1/plans
 * Returns authoritative server-side public plan catalogue.
 * Strictly public fields only: stable IDs, names, intervals, quotas, and feature entitlements.
 */
export async function GET() {
  try {
    const plans = getPublicCatalog();
    return NextResponse.json(
      {
        success: true,
        plans,
      },
      {
        status: 200,
        headers: {
          "Cache-Control": "public, s-maxage=3600, stale-while-revalidate=86400",
        },
      }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to load product catalogue";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
