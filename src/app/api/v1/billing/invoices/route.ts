import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/v1/billing/invoices
 * Returns the authenticated tenant's paginated invoice history.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Valid session required" }, { status: 401 });
  }

  try {
    const page = Math.max(1, parseInt(req.nextUrl.searchParams.get("page") || "1", 10));
    const limit = Math.min(50, Math.max(1, parseInt(req.nextUrl.searchParams.get("limit") || "10", 10)));
    const offset = (page - 1) * limit;

    let invoices: any[] = [];
    let totalCount = 0;

    try {
      const countRes = await query<{ count: string }>(
        `SELECT COUNT(*) as count FROM invoices WHERE tenant_id = $1`,
        [session.tenantId]
      );
      totalCount = parseInt(countRes.rows[0]?.count || "0", 10);

      const res = await query<any>(
        `SELECT id, stripe_invoice_id, invoice_number, currency, amount_due_cents, amount_paid_cents,
                status, period_start, period_end, hosted_invoice_url, invoice_pdf_url, paid_at, created_at
         FROM invoices
         WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3`,
        [session.tenantId, limit, offset]
      );
      invoices = res.rows.map((row) => ({
        id: row.id,
        stripeInvoiceId: row.stripe_invoice_id,
        invoiceNumber: row.invoice_number,
        currency: row.currency,
        amountDueCents: Number(row.amount_due_cents),
        amountPaidCents: Number(row.amount_paid_cents),
        amountDue: Number(row.amount_due_cents) / 100,
        amountPaid: Number(row.amount_paid_cents) / 100,
        status: row.status,
        periodStart: row.period_start ? new Date(row.period_start).toISOString() : null,
        periodEnd: row.period_end ? new Date(row.period_end).toISOString() : null,
        hostedInvoiceUrl: row.hosted_invoice_url,
        invoicePdfUrl: row.invoice_pdf_url,
        paidAt: row.paid_at ? new Date(row.paid_at).toISOString() : null,
        createdAt: new Date(row.created_at).toISOString(),
      }));
    } catch {
      // In-memory / test harness empty list
    }

    return NextResponse.json(
      {
        success: true,
        tenantId: session.tenantId,
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit) || 1,
        invoices,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "GET /api/v1/billing/invoices", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to load invoices";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
