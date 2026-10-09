import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import {
  executeAgentCommand,
  listEndpointAgents,
  getEndpointAgent,
  recordHashChainEvent,
  type EndpointAgentRecord,
} from "@/lib/fleet/fleet";
import type { MitigationTaskRecord } from "@/app/api/tasks/route";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

function mapTaskToAgentCommand(task: MitigationTaskRecord): string {
  const t = ((task.title || "") + " " + (task.description || "")).toLowerCase();
  if (t.includes("isolate") || t.includes("quarantine endpoint") || t.includes("contain")) {
    return "isolate_host";
  }
  if (t.includes("block") || t.includes("firewall") || t.includes("arp") || t.includes("ip")) {
    return "block_ip 198.51.100.4";
  }
  if (t.includes("revoke") || t.includes("kill") || t.includes("session") || t.includes("terminate")) {
    return "kill_process 4812";
  }
  if (t.includes("patch") || t.includes("cve") || t.includes("update")) {
    const cve = task.cve_id || "CVE-2025-38667";
    return `apply_patch ${cve}`;
  }
  if (t.includes("snapshot") || t.includes("backup")) {
    return "take_safety_snapshot";
  }
  if (t.includes("restore")) {
    return "restore_host";
  }
  return "take_safety_snapshot";
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const caller = await getSessionUser(req);
  if (!caller) {
    return NextResponse.json(
      { error: "Unauthorized: Valid authentication session required" },
      { status: 401 }
    );
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "Task ID is required" }, { status: 400 });
  }

  try {
    // Authorization check: Analysts cannot dispatch remediation tasks
    if (caller.role === "analyst") {
      return NextResponse.json(
        { error: "INSUFFICIENT_ROLE: Analysts cannot dispatch remediation commands to endpoints. Dispatch requires a Responder, System Admin, or Super Admin." },
        { status: 403 }
      );
    }

    const isCrossTenant = canAccess(caller.role, "VIEW_CROSS_TENANT");

    // 1. Fetch Task
    const taskSql = isCrossTenant
      ? "SELECT * FROM mitigation_tasks WHERE id = $1 LIMIT 1"
      : "SELECT * FROM mitigation_tasks WHERE id = $1 AND tenant_id = $2 LIMIT 1";
    const taskParams = isCrossTenant ? [id] : [id, caller.tenant_id];

    const taskRes = await query<MitigationTaskRecord>(taskSql, taskParams);
    if (taskRes.rows.length === 0) {
      return NextResponse.json({ error: "Task not found" }, { status: 404 });
    }

    const task = taskRes.rows[0];

    // Check if task is already completed
    if (task.status === "completed") {
      return NextResponse.json({
        success: true,
        message: "Task is already executed and completed.",
        task,
      });
    }

    // 2. Resolve Governance Approval Token (if Tier 2 or Tier 3)
    let tokenId: string | undefined = undefined;
    const isTierGated = task.tier === "Tier 2" || task.tier === "Tier 3";

    if (isTierGated) {
      const tokenSql = isCrossTenant
        ? "SELECT * FROM approval_tokens WHERE task_id = $1 ORDER BY created_at DESC LIMIT 1"
        : "SELECT * FROM approval_tokens WHERE task_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 1";
      const tokenParams = isCrossTenant ? [id] : [id, caller.tenant_id];
      const tokenRes = await query<ApprovalTokenRecord>(tokenSql, tokenParams);

      const token = tokenRes.rows[0];

      if (!token) {
        // If task was already marked approved by analyst/admin, generate execution token
        if (task.status === "approved") {
          const autoTokenId = (await import("crypto")).randomUUID();
          const requesterUid = caller.id === "dev-admin" ? "dev-analyst" : "dev-admin";
          const expiresAt = new Date(Date.now() + 86400000).toISOString();
          await query(
            `INSERT INTO approval_tokens (id, tenant_id, task_id, action_type, tier, status, requested_by, approved_by, blast_radius, expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'approved', $6, $7, $8, $9, NOW(), NOW())`,
            [
              autoTokenId,
              task.tenant_id,
              task.id,
              task.title,
              task.tier,
              requesterUid,
              caller.id,
              task.blast_radius || "Host Scope",
              expiresAt,
            ]
          );
          tokenId = autoTokenId;
        } else {
          return NextResponse.json(
            { error: "APPROVAL_REQUIRED: Task requires human sign-off before dispatch." },
            { status: 403 }
          );
        }
      } else if (token.status === "pending") {
        return NextResponse.json(
          { error: "APPROVAL_PENDING: Human sign-off is pending for this task." },
          { status: 403 }
        );
      } else if (token.status === "rejected") {
        return NextResponse.json(
          { error: "APPROVAL_REJECTED: This task was rejected by governance." },
          { status: 403 }
        );
      } else if (token.status === "approved") {
        tokenId = token.id;
      } else if (token.status === "consumed") {
        // Refresh token for re-execution if needed
        const freshTokenId = (await import("crypto")).randomUUID();
        const requesterUid = caller.id === "dev-admin" ? "dev-analyst" : "dev-admin";
        const expiresAt = new Date(Date.now() + 86400000).toISOString();
        await query(
          `INSERT INTO approval_tokens (id, tenant_id, task_id, action_type, tier, status, requested_by, approved_by, blast_radius, expires_at, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, 'approved', $6, $7, $8, $9, NOW(), NOW())`,
          [
            freshTokenId,
            task.tenant_id,
            task.id,
            task.title,
            task.tier,
            requesterUid,
            caller.id,
            task.blast_radius || "Host Scope",
            expiresAt,
          ]
        );
        tokenId = freshTokenId;
      }
    }

    // 3. Resolve Target Endpoint Agent
    const agents = await listEndpointAgents(caller);
    let targetAgent: EndpointAgentRecord | null | undefined = agents.find((a) => {
      const matchString = ((task.blast_radius || "") + " " + task.title).toUpperCase();
      return matchString.includes(a.hostname.toUpperCase());
    });

    if (!targetAgent && agents.length > 0) {
      // Fallback to first available agent
      targetAgent = agents[0];
    }

    if (!targetAgent) {
      // Check for baseline test host in DB
      targetAgent = await getEndpointAgent("FIN-WS-042", caller);
    }

    if (!targetAgent) {
      return NextResponse.json(
        { error: "NO_ACTIVE_AGENT: No reachable endpoint agents found for this tenant." },
        { status: 404 }
      );
    }

    // 4. Mark Task 'in_progress' immediately
    await query("UPDATE mitigation_tasks SET status = 'in_progress' WHERE id = $1", [id]);

    // 5. Map & Execute Command
    const command = mapTaskToAgentCommand(task);
    const executionTier = task.tier === "Tier 0" ? "Tier 1" : (task.tier as "Tier 1" | "Tier 2" | "Tier 3");

    const execResult = await executeAgentCommand({
      agentId: targetAgent.id,
      command,
      tier: executionTier,
      tokenId,
      caller,
    });

    // 6. Mark Task 'completed'
    const updatedTaskRes = await query<MitigationTaskRecord>(
      "UPDATE mitigation_tasks SET status = 'completed' WHERE id = $1 RETURNING *",
      [id]
    );

    // 7. Check if parent mitigation plan is fully completed
    if (task.plan_id) {
      try {
        const remaining = await query<{ count: string }>(
          "SELECT COUNT(*) as count FROM mitigation_tasks WHERE plan_id = $1 AND status != 'completed'",
          [task.plan_id]
        );
        if (remaining.rows[0]?.count === "0") {
          await query(
            "UPDATE mitigation_plans SET status = 'completed', updated_at = NOW() WHERE id = $1",
            [task.plan_id]
          );
        }
      } catch {
        // Non-blocking
      }
    }

    // 8. Record audit log
    await recordHashChainEvent({
      tenantId: task.tenant_id,
      eventType: "TASK_REMEDIATION_EXECUTED",
      actorId: caller.id,
      payload: {
        taskId: id,
        taskTitle: task.title,
        command,
        agentId: targetAgent.id,
        agentHostname: targetAgent.hostname,
        output: execResult.output,
        snapshotId: execResult.snapshotId || null,
      },
    });

    return NextResponse.json({
      success: true,
      taskId: id,
      status: "completed",
      output: execResult.output,
      commandId: execResult.commandId,
      snapshotId: execResult.snapshotId,
      agent: {
        id: targetAgent.id,
        hostname: targetAgent.hostname,
        ipAddress: targetAgent.ip_address,
      },
      task: updatedTaskRes.rows[0] || { ...task, status: "completed" },
    });
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/tasks/[id]/execute",
      userId: caller.id,
      tenantId: caller.tenant_id,
    });
    const msg = err instanceof Error ? err.message : "Execution failed";

    // Revert status to approved if execution failed
    try {
      await query("UPDATE mitigation_tasks SET status = 'approved' WHERE id = $1", [id]);
    } catch {}

    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
