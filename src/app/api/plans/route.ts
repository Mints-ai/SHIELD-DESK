import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import { isDemoModeActive } from "@/lib/config/environment";

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
  created_at: string;
}

const FALLBACK_PLANS: Record<string, PlanSummaryRecord[]> = {
  "acme-tenant": [
    {
      id: "p1111111-1111-1111-1111-111111111111",
      incident_id: "11111111-1111-1111-1111-111111111111",
      incident_code: "INC-1042",
      incident_title: "Active Exploitation of Edge VPN Gateway (CVE-2024-3400)",
      incident_severity: "critical",
      status: "in_progress",
      version: 1,
      summary:
        "Emergency containment protocol for PAN-OS GlobalProtect command injection. Isolates VPN gateway, revokes active sessions, and applies hotfix hotfix-panos-10.2.9-h1.",
      task_count: 5,
      created_at: "2026-09-23T20:00:00Z",
    },
    {
      id: "p2222222-2222-2222-2222-222222222222",
      incident_id: "22222222-2222-2222-2222-222222222222",
      incident_code: "INC-1043",
      incident_title: "Privilege Escalation on Finance Workstation WS-FIN-08",
      incident_severity: "high",
      status: "draft",
      version: 1,
      summary:
        "Lateral movement prevention and local admin credential rotation following anomalous LSASS memory access detection.",
      task_count: 4,
      created_at: "2026-09-23T19:15:00Z",
    },
    {
      id: "p3333333-3333-3333-3333-333333333333",
      incident_id: "33333333-3333-3333-3333-333333333333",
      incident_code: "INC-1044",
      incident_title: "Suspicious PowerShell Execution via Macro Attachment",
      incident_severity: "medium",
      status: "completed",
      version: 2,
      summary:
        "Phishing triage and payload detonation analysis. Quarantined malicious macro template and blocked domain telemetry at firewall perimeter.",
      task_count: 3,
      created_at: "2026-09-23T18:30:00Z",
    },
  ],
  "globex-tenant": [],
};

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
               COUNT(t.id)::int as task_count
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
             incident_code, incident_title, incident_severity, task_count
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
    if (isDemoModeActive()) {
      const plans = FALLBACK_PLANS[session.tenantId] || [];
      return NextResponse.json({
        plans,
        count: plans.length,
        tenantId: session.tenantId,
        _source: "demo_fallback",
      });
    }

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
