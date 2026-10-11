import { NextRequest, NextResponse } from "next/server";
import {
  getAllCustomerDocs,
  getCustomerDocById,
  generateDocumentationBundle,
} from "@/lib/docs/customerDocs";

export const dynamic = "force-dynamic";

/**
 * GET /api/docs
 *
 * Public Customer Documentation API Endpoint.
 * - `GET /api/docs`: returns list of customer documents with metadata.
 * - `GET /api/docs?id=<doc_id>`: returns individual document.
 * - `GET /api/docs?format=bundle`: returns unified markdown manual.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const docId = searchParams.get("id");
  const format = searchParams.get("format");

  if (format === "bundle") {
    const bundle = generateDocumentationBundle();
    return new Response(bundle, {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": 'attachment; filename="ShieldDesk-Customer-Manual.md"',
        "Cache-Control": "public, max-age=3600",
      },
    });
  }

  if (docId) {
    const doc = getCustomerDocById(docId);
    if (!doc) {
      return NextResponse.json(
        { error: `Document '${docId}' not found` },
        { status: 404 }
      );
    }
    return NextResponse.json({ document: doc });
  }

  const docs = getAllCustomerDocs();
  return NextResponse.json({
    total: docs.length,
    documents: docs,
  });
}
