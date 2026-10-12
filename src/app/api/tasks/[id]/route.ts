import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest, getSessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import { isDemoModeActive } from "@/lib/config/environment";
import type { MitigationTaskRecord } from "@/app/api/tasks/route";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "Task ID is required" }, { status: 400 });
  }

  try {
    const isCrossTenant = canAccess(session.role, "VIEW_CROSS_TENANT");
    const sql = isCrossTenant
      ? `
        SELECT t.id, t.plan_id, t.tenant_id, t.horizon, t.title, t.description,
               t.tier, t.status, t.blast_radius, t.cve_id, t.assigned_to, t.created_at,
               i.incident_code, i.title as incident_title, i.severity as incident_severity,
               p.version as plan_version, p.status as plan_status
        FROM mitigation_tasks t
        LEFT JOIN mitigation_plans p ON p.id = t.plan_id
        LEFT JOIN incidents i ON i.id = p.incident_id
        WHERE t.id = $1
        LIMIT 1
      `
      : `
        SELECT t.id, t.plan_id, t.tenant_id, t.horizon, t.title, t.description,
               t.tier, t.status, t.blast_radius, t.cve_id, t.assigned_to, t.created_at,
               i.incident_code, i.title as incident_title, i.severity as incident_severity,
               p.version as plan_version, p.status as plan_status
        FROM mitigation_tasks t
        LEFT JOIN mitigation_plans p ON p.id = t.plan_id
        LEFT JOIN incidents i ON i.id = p.incident_id
        WHERE t.id = $1 AND t.tenant_id = $2
        LIMIT 1
      `;
    const paramsList = isCrossTenant ? [id] : [id, session.tenantId];
    const taskRes = await query<MitigationTaskRecord & {
      incident_title?: string;
      incident_severity?: string;
      plan_version?: number;
      plan_status?: string;
    }>(sql, paramsList);

    if (taskRes.rows.length === 0) {
      return NextResponse.json({ error: "Task not found" }, { status: 404 });
    }

    const task = taskRes.rows[0];

    // Fetch related approval tokens
    const tokenSql = isCrossTenant
      ? "SELECT * FROM approval_tokens WHERE task_id = $1 ORDER BY created_at DESC"
      : "SELECT * FROM approval_tokens WHERE task_id = $1 AND tenant_id = $2 ORDER BY created_at DESC";
    const tokenParams = isCrossTenant ? [id] : [id, session.tenantId];
    const tokensRes = await query<{ id: string }>(tokenSql, tokenParams).catch(() => ({ rows: [] as Array<{ id: string }> }));

    // Fetch related command logs if any
    let commandLogs: unknown[] = [];
    if (tokensRes.rows.length > 0) {
      const tokenIds = tokensRes.rows.map((t) => t.id);
      const logsRes = await query(
        "SELECT * FROM agent_command_logs WHERE token_id = ANY($1::uuid[]) ORDER BY executed_at DESC",
        [tokenIds]
      ).catch(() => ({ rows: [] }));
      commandLogs = logsRes.rows;
    }

    return NextResponse.json({
      task,
      approvalTokens: tokensRes.rows,
      commandLogs,
    });
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/tasks/[id] (GET)",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json(
      { error: "Failed to retrieve mitigation task" },
      { status: 500 }
    );
  }
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "Task ID is required" }, { status: 400 });
  }

  // Analysts are read-only viewers and cannot edit tasks
  if (session.role === "analyst") {
    return NextResponse.json(
      { error: "INSUFFICIENT_ROLE: Analysts have read-only access and cannot edit tasks." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const isCrossTenant = canAccess(session.role, "VIEW_CROSS_TENANT");

    // First retrieve existing task
    const checkSql = isCrossTenant
      ? "SELECT * FROM mitigation_tasks WHERE id = $1 LIMIT 1"
      : "SELECT * FROM mitigation_tasks WHERE id = $1 AND tenant_id = $2 LIMIT 1";
    const checkParams = isCrossTenant ? [id] : [id, session.tenantId];
    const existing = await query<MitigationTaskRecord>(checkSql, checkParams);

    if (existing.rows.length === 0) {
      return NextResponse.json({ error: "Task not found" }, { status: 404 });
    }

    const currentTask = existing.rows[0];
    const allowedStatuses = ["pending", "approved", "rejected", "in_progress", "completed"];
    const newStatus = body.status && allowedStatuses.includes(body.status)
      ? body.status
      : currentTask.status;

    const newTitle = typeof body.title === "string" && body.title.trim()
      ? body.title.trim()
      : currentTask.title;

    const newDescription = typeof body.description === "string"
      ? body.description.trim()
      : currentTask.description;

    const newHorizon = ["immediate", "short_term", "long_term"].includes(body.horizon)
      ? body.horizon
      : currentTask.horizon;

    const newBlastRadius = typeof body.blastRadius === "string"
      ? body.blastRadius.trim()
      : currentTask.blast_radius;

    const newPlanId = typeof body.planId === "string" && body.planId.trim()
      ? body.planId.trim()
      : currentTask.plan_id;

    const newTier = ["Tier 1", "Tier 2", "Tier 3"].includes(body.tier)
      ? body.tier
      : currentTask.tier;

    const newAssignedTo = body.assignedTo !== undefined
      ? (body.assignedTo ? String(body.assignedTo).trim() : null)
      : body.assigned_to !== undefined
        ? (body.assigned_to ? String(body.assigned_to).trim() : null)
        : currentTask.assigned_to;

    const updateSql = `
      UPDATE mitigation_tasks
      SET status = $1, title = $2, description = $3, horizon = $4, blast_radius = $5, plan_id = $6, tier = $7, assigned_to = $8
      WHERE id = $9
      RETURNING *;
    `;

    const updateRes = await query<MitigationTaskRecord>(updateSql, [
      newStatus,
      newTitle,
      newDescription,
      newHorizon,
      newBlastRadius,
      newPlanId,
      newTier,
      newAssignedTo,
      id,
    ]);

    const updatedTask = updateRes.rows[0];

    // Synchronize pending approval tokens if the autonomy tier was updated
    if (body.tier && ["Tier 1", "Tier 2", "Tier 3"].includes(body.tier)) {
      await query(
        "UPDATE approval_tokens SET tier = $1, updated_at = now() WHERE task_id = $2 AND status = 'pending'",
        [newTier, id]
      ).catch((err) => console.error("Failed to update pending token tier:", err));
    }

    // If marked completed, check if all tasks under the parent plan are completed
    if (newStatus === "completed" && updatedTask?.plan_id) {
      try {
        const remainingIncomplete = await query<{ count: string }>(
          `SELECT COUNT(*) as count FROM mitigation_tasks WHERE plan_id = $1 AND status != 'completed'`,
          [updatedTask.plan_id]
        );
        if (remainingIncomplete.rows[0]?.count === "0") {
          await query(
            `UPDATE mitigation_plans SET status = 'completed', updated_at = NOW() WHERE id = $1`,
            [updatedTask.plan_id]
          );
        }
      } catch {
        // Non-fatal
      }
    }

    return NextResponse.json({
      success: true,
      task: updatedTask,
    });
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/tasks/[id] (PATCH)",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json(
      { error: "Failed to update mitigation task" },
      { status: 500 }
    );
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "Task ID is required" }, { status: 400 });
  }

  // Analysts are read-only viewers and cannot delete tasks
  if (session.role === "analyst") {
    return NextResponse.json(
      { error: "INSUFFICIENT_ROLE: Analysts have read-only access and cannot delete tasks." },
      { status: 403 }
    );
  }

  try {
    const isCrossTenant = canAccess(session.role, "VIEW_CROSS_TENANT");

    // Explicitly clean up any related tokens and command logs to prevent FK constraint violations
    const tokenCheckSql = isCrossTenant
      ? "SELECT id FROM approval_tokens WHERE task_id = $1"
      : "SELECT id FROM approval_tokens WHERE task_id = $1 AND tenant_id = $2";
    const tokenCheckParams = isCrossTenant ? [id] : [id, session.tenantId];
    const tokensRes = await query<{ id: string }>(tokenCheckSql, tokenCheckParams).catch(() => ({ rows: [] as Array<{ id: string }> }));

    if (tokensRes.rows.length > 0) {
      const tokenIds = tokensRes.rows.map((t) => t.id);
      await query("DELETE FROM agent_command_logs WHERE token_id = ANY($1::uuid[])", [tokenIds]).catch(() => {});
      await query("DELETE FROM agent_commands WHERE token_id = ANY($1::uuid[])", [tokenIds]).catch(() => {});
      await query("DELETE FROM approval_audit_log WHERE token_id = ANY($1::uuid[])", [tokenIds]).catch(() => {});
      await query("DELETE FROM approval_tokens WHERE id = ANY($1::uuid[])", [tokenIds]).catch(() => {});
    }

    const deleteSql = isCrossTenant
      ? "DELETE FROM mitigation_tasks WHERE id = $1 RETURNING id"
      : "DELETE FROM mitigation_tasks WHERE id = $1 AND tenant_id = $2 RETURNING id";
    const deleteParams = isCrossTenant ? [id] : [id, session.tenantId];

    const res = await query(deleteSql, deleteParams);
    if (res.rows.length === 0) {
      return NextResponse.json({ error: "Task not found" }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      deletedId: id,
    });
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/tasks/[id] (DELETE)",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json(
      { error: "Failed to delete mitigation task" },
      { status: 500 }
    );
  }
}
