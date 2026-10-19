import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess, canAssignTask, getRoleTier } from "@/lib/permissions";
import { getUserRole } from "@/lib/constants/devUsers";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import { requestApprovalToken } from "@/lib/governance/approvalTokens";
import crypto from "crypto";

export interface MitigationTaskRecord {
  id: string;
  plan_id: string;
  tenant_id: string;
  horizon: "immediate" | "short_term" | "long_term";
  title: string;
  description: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  status: "pending" | "approved" | "rejected" | "in_progress" | "completed" | "failed";
  blast_radius?: string | null;
  cve_id?: string | null;
  assigned_to?: string | null;
  execution_command_id?: string | null;
  incident_code?: string;
  created_at: string;
}



export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const planId = searchParams.get("planId");
  const horizon = searchParams.get("horizon");
  const status = searchParams.get("status");

  try {
    const isCrossTenant = canAccess(session.role, "VIEW_CROSS_TENANT");
    let querySql = `
      SELECT t.id, t.plan_id, t.tenant_id, t.horizon, t.title, t.description,
             t.tier, t.status, t.blast_radius, t.cve_id, t.assigned_to, t.created_at,
             i.incident_code
      FROM mitigation_tasks t
      LEFT JOIN mitigation_plans p ON p.id = t.plan_id
      LEFT JOIN incidents i ON i.id = p.incident_id
      WHERE 1=1
    `;
    const params: unknown[] = [];

    if (!isCrossTenant) {
      params.push(session.tenantId);
      querySql += ` AND t.tenant_id = $${params.length}`;
    }

    if (planId) {
      params.push(planId);
      querySql += ` AND t.plan_id = $${params.length}`;
    }

    if (horizon && horizon !== "all") {
      params.push(horizon);
      querySql += ` AND t.horizon = $${params.length}`;
    }

    if (status && status !== "all") {
      params.push(status);
      querySql += ` AND t.status = $${params.length}`;
    }

    querySql += " ORDER BY t.created_at DESC";

    const res = await query<MitigationTaskRecord>(querySql, params);
    return NextResponse.json({
      tasks: res.rows,
      count: res.rows.length,
      tenantId: session.tenantId,
      _source: "database",
    });
  } catch (err) {
    trackError(err, {
      endpoint: "/api/tasks",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json(
      { error: "Failed to retrieve mitigation tasks from database" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!canAssignTask(session.role, session.tenantId)) {
    return NextResponse.json(
      { error: "Insufficient permissions to draft mitigation tasks" },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    // Authorization check: Analysts have read-only access and cannot create or assign tasks
    if (session.role === "analyst") {
      return NextResponse.json(
        { error: "INSUFFICIENT_ROLE: Analysts have read-only access and cannot create or assign tasks." },
        { status: 403 }
      );
    }

    const title = typeof body.title === "string" ? body.title.trim() : "";
    const description = typeof body.description === "string" ? body.description.trim() : "Custom task";
    const horizon = ["immediate", "short_term", "long_term"].includes(body.horizon)
      ? body.horizon
      : "immediate";
    const tier = ["Tier 0", "Tier 1", "Tier 2", "Tier 3"].includes(body.tier)
      ? body.tier
      : "Tier 2";
    const blastRadius = typeof body.blastRadius === "string" ? body.blastRadius : "Host Scope";
    const cveId = typeof body.cveId === "string" ? body.cveId : null;
    const assignedTo = typeof body.assignedTo === "string" && body.assignedTo.trim()
      ? body.assignedTo.trim()
      : typeof body.assigned_to === "string" && body.assigned_to.trim()
        ? body.assigned_to.trim()
        : null;

    if (!title) {
      return NextResponse.json({ error: "Task title is required" }, { status: 400 });
    }

    // Role Hierarchy Constraint: Lower tier employee cannot assign a task to a higher tier employee
    if (assignedTo) {
      let assigneeRole: string | null = getUserRole(assignedTo);
      if (!assigneeRole) {
        try {
          const userRes = await query<{ role: string }>(
            "SELECT role FROM users WHERE id = $1 OR email = $1 LIMIT 1",
            [assignedTo]
          );
          if (userRes.rows.length > 0) {
            assigneeRole = userRes.rows[0].role;
          }
        } catch {
          // DB error fallback
        }
      }

      if (assigneeRole) {
        const assignerTier = getRoleTier(session.role);
        const assigneeTier = getRoleTier(assigneeRole);
        if (assignerTier < assigneeTier) {
          return NextResponse.json(
            {
              error: `HIERARCHY_VIOLATION: Lower tier employee (${session.role}) cannot assign a task to higher tier employee (${assigneeRole}).`,
            },
            { status: 403 }
          );
        }
      }
    }

    const taskId = crypto.randomUUID();
    let planId = body.planId && typeof body.planId === "string" && body.planId.trim()
      ? body.planId.trim()
      : null;

    // If planId specified, verify it belongs to caller's tenant
    if (planId) {
      try {
        const checkSql = canAccess(session.role, "VIEW_CROSS_TENANT")
          ? "SELECT id, tenant_id FROM mitigation_plans WHERE id = $1 LIMIT 1"
          : "SELECT id, tenant_id FROM mitigation_plans WHERE id = $1 AND tenant_id = $2 LIMIT 1";
        const checkParams = canAccess(session.role, "VIEW_CROSS_TENANT")
          ? [planId]
          : [planId, session.tenantId];
        const planCheck = await query<{ id: string; tenant_id: string }>(checkSql, checkParams);
        if (planCheck.rows.length === 0) {
          planId = null; // Do not fail task creation; treat as standalone task
        }
      } catch {
        planId = null;
      }
    }

    try {
      const insertSql = `
        INSERT INTO mitigation_tasks (
          id, plan_id, tenant_id, horizon, title, description, tier, status, blast_radius, cve_id, assigned_to, created_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, NOW()
        )
        RETURNING id, plan_id, tenant_id, horizon, title, description, tier, status, blast_radius, cve_id, assigned_to, created_at
      `;
      const res = await query<MitigationTaskRecord>(insertSql, [
        taskId,
        planId,
        session.tenantId,
        horizon,
        title,
        description,
        tier,
        blastRadius,
        cveId,
        assignedTo,
      ]);

      if (tier !== "Tier 0") {
        try {
          await requestApprovalToken(session, {
            taskId,
            actionType: title,
            blastRadius,
            tier,
          });
        } catch {
          // Token creation is non-blocking
        }
      }

      return NextResponse.json({
        success: true,
        task: res.rows[0],
        _source: "database",
      });
    } catch (dbErr) {
      trackError(dbErr, {
        endpoint: "/api/tasks (POST)",
        userId: session.uid,
        tenantId: session.tenantId,
      });
      return NextResponse.json(
        { error: "Failed to persist mitigation task" },
        { status: 500 }
      );
    }
  } catch (err) {
    trackError(err, {
      endpoint: "/api/tasks (POST payload)",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json({ error: "Malformed task request payload" }, { status: 400 });
  }
}
