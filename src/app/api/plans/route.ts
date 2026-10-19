import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";

export interface PlanSummaryRecord {
  id: string;
  incident_id: string;
  incident_code: string;
  incident_title: string;
  incident_severity: string;
  status: string;
  version: number;
  summary: string;
  task_count: number;
  completed_task_count: number;
  created_at: string;
}

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const isCrossTenant = canAccess(session.role, "VIEW_CROSS_TENANT");
    let sql = `
      WITH plan_summaries AS (
        SELECT p.id, p.incident_id, p.tenant_id, p.version, p.status, p.summary, p.created_at,
               i.incident_code, i.title as incident_title, i.severity as incident_severity,
               COUNT(t.id)::int as task_count,
               COUNT(CASE WHEN t.status = 'completed' THEN 1 END)::int as completed_task_count
        FROM mitigation_plans p
        LEFT JOIN incidents i ON i.id = p.incident_id
        LEFT JOIN mitigation_tasks t ON t.plan_id = p.id
        WHERE 1=1
    `;
    const params: unknown[] = [];

    if (!isCrossTenant) {
      params.push(session.tenantId);
      sql += ` AND p.tenant_id = $${params.length}`;
    }

    sql += `
        GROUP BY p.id, p.incident_id, p.tenant_id, p.version, p.status, p.summary, p.created_at,
                 i.incident_code, i.title, i.severity
      ),
      ranked_plans AS (
        SELECT plan_summaries.*,
               ROW_NUMBER() OVER (
                 PARTITION BY tenant_id, incident_id,
                   CASE
                     WHEN status IN ('draft', 'active') THEN 'current'
                     ELSE id::text
                   END
                 ORDER BY version DESC, created_at DESC, id DESC
               ) AS incident_plan_rank
        FROM plan_summaries
      )
      SELECT id, incident_id, tenant_id, version, status, summary, created_at,
             incident_code, incident_title, incident_severity, task_count, completed_task_count
      FROM ranked_plans
      WHERE incident_plan_rank = 1
      ORDER BY created_at DESC
    `;

    const res = await query<PlanSummaryRecord>(sql, params);
    return NextResponse.json({
      plans: res.rows,
      count: res.rows.length,
      tenantId: session.tenantId,
      _source: "database",
    });
  } catch (err) {
    trackError(err, {
      endpoint: "/api/plans",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json(
      { error: "Failed to retrieve mitigation plans from database" },
      { status: 500 }
    );
  }
}
