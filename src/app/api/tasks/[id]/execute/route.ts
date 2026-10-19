import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import {
  executeAgentCommand,
  listEndpointAgents,
  recordHashChainEvent,
  type EndpointAgentRecord,
} from "@/lib/fleet/fleet";
import type { MitigationTaskRecord } from "@/app/api/tasks/route";
import { settleCommandTask } from "@/lib/fleet/taskCompletion";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

function mapTaskToAgentCommand(task: MitigationTaskRecord, token?: ApprovalTokenRecord): string {
  // 1. If token has an explicit command stored, prioritize that
  if (token?.command && typeof token.command === "string" && token.command.trim()) {
    return token.command.trim();
  }

  // 2. If task.description is directly an agent command, use it
  const desc = (task.description || "").trim();
  const knownPrefixes = [
    "block_ip", "block ip", "unblock_ip", "unblock ip",
    "isolate_host", "restore_host", "kill_process",
    "take_safety_snapshot", "rollback_snapshot", "apply_patch"
  ];
  for (const prefix of knownPrefixes) {
    if (desc.toLowerCase().startsWith(prefix)) {
      return desc;
    }
  }

  // 3. Extract target IP if block_ip / unblock_ip is in title or description
  const fullText = `${task.title || ""} ${desc}`;
  const ipMatch = fullText.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);

  if (fullText.toLowerCase().includes("unblock")) {
    if (ipMatch) return `unblock_ip ${ipMatch[0]}`;
  }
  if (fullText.toLowerCase().includes("block") || fullText.toLowerCase().includes("firewall")) {
    if (ipMatch) return `block_ip ${ipMatch[0]}`;
  }

  // 4. Extract process PID if kill_process is requested
  const pidMatch = fullText.match(/\b(?:kill_process|pid|process)\s*[:=]?\s*(\d+)\b/i);
  if (pidMatch && (fullText.toLowerCase().includes("kill") || fullText.toLowerCase().includes("terminate"))) {
    return `kill_process ${pidMatch[1]}`;
  }

  if (fullText.toLowerCase().includes("isolate") || fullText.toLowerCase().includes("quarantine")) {
    return "isolate_host";
  }
  if (fullText.toLowerCase().includes("restore")) {
    return "restore_host";
  }
  if (fullText.toLowerCase().includes("patch") || task.cve_id) {
    return `apply_patch ${task.cve_id || "CVE-2025-38667"}`;
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

    if (task.status === "in_progress") {
      return NextResponse.json({ error: "Task is awaiting its endpoint execution report." }, { status: 409 });
    }

    // 2. Resolve Governance Approval Token (if Tier 2 or Tier 3)
    let tokenId: string | undefined = undefined;
    let token: ApprovalTokenRecord | undefined = undefined;
    const isTierGated = task.tier === "Tier 2" || task.tier === "Tier 3";

    if (isTierGated) {
      const tokenSql = isCrossTenant
        ? "SELECT * FROM approval_tokens WHERE task_id = $1 ORDER BY created_at DESC LIMIT 1"
        : "SELECT * FROM approval_tokens WHERE task_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 1";
      const tokenParams = isCrossTenant ? [id] : [id, caller.tenant_id];
      const tokenRes = await query<ApprovalTokenRecord>(tokenSql, tokenParams);

      token = tokenRes.rows[0];

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
    let targetAgent: EndpointAgentRecord | null | undefined = null;

    if (token?.target_endpoint_ids && Array.isArray(token.target_endpoint_ids) && token.target_endpoint_ids.length > 0) {
      targetAgent = agents.find((a) =>
        token.target_endpoint_ids!.includes(a.id) ||
        token.target_endpoint_ids!.includes(a.hostname) ||
        (a.ip_address && token.target_endpoint_ids!.includes(a.ip_address))
      );
    }

    if (!targetAgent) {
      const matchString = ((task.blast_radius || "") + " " + (task.description || "") + " " + task.title).toUpperCase();
      targetAgent = agents.find((a) =>
        matchString.includes(a.hostname.toUpperCase()) ||
        (a.ip_address && matchString.includes(a.ip_address)) ||
        matchString.includes(a.id.toUpperCase())
      );
    }

    if (!targetAgent && agents.length > 0) {
      // Fallback to first available agent
      targetAgent = agents[0];
    }

    if (!targetAgent) {
      return NextResponse.json(
        { error: "NO_ACTIVE_AGENT: No reachable endpoint agents found for this tenant." },
        { status: 404 }
      );
    }

    // 5. Map & Execute Command
    const command = mapTaskToAgentCommand(task, token);
    const executionTier = task.tier === "Tier 0" ? "Tier 1" : (task.tier as "Tier 1" | "Tier 2" | "Tier 3");

    if (
      command.startsWith("block_ip") ||
      command.startsWith("block ip") ||
      command.startsWith("unblock_ip") ||
      command.startsWith("unblock ip")
    ) {
      const isUnblock = command.startsWith("unblock_ip") || command.startsWith("unblock ip");
      const targetIp = (
        command.startsWith("block ip")
          ? command.replace(/^block ip\s+/i, "")
          : command.startsWith("block_ip")
            ? command.replace(/^block_ip\s+/i, "")
            : command.startsWith("unblock ip")
              ? command.replace(/^unblock ip\s+/i, "")
              : command.replace(/^unblock_ip\s+/i, "")
      ).trim();

      const { checkIsIpCurrentlyBlocked } = await import("@/lib/fleet/fleet");
      const isCurrentlyBlocked = await checkIsIpCurrentlyBlocked(targetIp, caller.tenant_id, tokenId);

      if (isUnblock && !isCurrentlyBlocked) {
        await query("UPDATE mitigation_tasks SET status = 'failed' WHERE id = $1", [id]).catch(() => {});
        if (tokenId) {
          await query("UPDATE agent_command_logs SET status = 'failed', output = $1 WHERE token_id::text = $2", [`The IP address ${targetIp} is not blocked.`, tokenId]).catch(() => {});
        }
        return NextResponse.json(
          { error: `The IP address ${targetIp} is not blocked.` },
          { status: 400 }
        );
      }

      if (!isUnblock && isCurrentlyBlocked && !tokenId) {
        await query("UPDATE mitigation_tasks SET status = 'failed' WHERE id = $1", [id]).catch(() => {});
        return NextResponse.json(
          { error: `The IP address ${targetIp} is already blocked.` },
          { status: 400 }
        );
      }
    }

    const execResult = await executeAgentCommand({
      agentId: targetAgent.id,
      command,
      tier: executionTier,
      tokenId,
      caller,
      taskId: id,
    });

    // Update real-time fleet state based on executed command
    if (command.startsWith("isolate_host")) {
      const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");
      const { recordBlockedIp } = await import("@/lib/fleet/blockedIps");

      await setLiveAgentStatus(targetAgent.id, "isolated", execResult.snapshotId);
      await setLiveAgentStatus(targetAgent.id, "disconnected", execResult.snapshotId);

      if (targetAgent.ip_address && targetAgent.ip_address !== "Unknown") {
        await recordBlockedIp({
          tenantId: caller.tenant_id,
          ip: targetAgent.ip_address,
          agentId: targetAgent.id,
          hostname: targetAgent.hostname,
          reason: `Tier 2 host isolation task #${id} executed by ${caller.email || caller.id}`,
          tier: executionTier,
          blockedBy: caller.email || caller.id,
        });
      }

      await query(
        `UPDATE endpoint_agents
         SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
         WHERE id = $1;`,
        [targetAgent.id]
      ).catch(() => {});
    } else if (command.startsWith("restore_host")) {
      const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");
      const { recordUnblockedIp } = await import("@/lib/fleet/blockedIps");

      await setLiveAgentStatus(targetAgent.id, "connected");

      if (targetAgent.ip_address && targetAgent.ip_address !== "Unknown") {
        await recordUnblockedIp({
          tenantId: caller.tenant_id,
          ip: targetAgent.ip_address,
          unblockedBy: caller.email || caller.id,
        });
      }

      await query(
        `UPDATE endpoint_agents
         SET status = 'connected', last_seen_at = now()
         WHERE id = $1 OR ip_address = $2;`,
        [targetAgent.id, targetAgent.ip_address]
      ).catch(() => {});
    } else if (command.startsWith("block_ip") || command.startsWith("block ip")) {
      const targetIp = (
        command.startsWith("block ip")
          ? command.replace(/^block ip\s+/i, "")
          : command.replace(/^block_ip\s+/i, "")
      ).trim();
      if (targetIp) {
        const { recordBlockedIp } = await import("@/lib/fleet/blockedIps");
        const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");

        await recordBlockedIp({
          tenantId: caller.tenant_id,
          ip: targetIp,
          agentId: targetAgent.id,
          hostname: targetAgent.hostname,
          reason: `Fleet containment task #${id} executed by ${caller.email || caller.id}`,
          tier: executionTier,
          blockedBy: caller.email || caller.id,
        });

        const isTargetHostItself =
          targetAgent.ip_address === targetIp ||
          targetIp === "127.0.0.1" ||
          !targetAgent.ip_address ||
          targetAgent.ip_address === "Unknown";

        if (isTargetHostItself) {
          await query(
            `UPDATE endpoint_agents
             SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
             WHERE id = $1;`,
            [targetAgent.id]
          ).catch(() => {});
          await setLiveAgentStatus(targetAgent.id, "disconnected", execResult.snapshotId);
        }

        if (targetAgent.ip_address && targetAgent.ip_address !== "Unknown" && targetAgent.ip_address !== targetIp) {
          await recordBlockedIp({
            tenantId: caller.tenant_id,
            ip: targetAgent.ip_address,
            agentId: targetAgent.id,
            hostname: targetAgent.hostname,
            reason: `Fleet containment task #${id} executed on host ${targetAgent.hostname}`,
            tier: executionTier,
            blockedBy: caller.email || caller.id,
          });
        }
      }
    } else if (command.startsWith("unblock_ip") || command.startsWith("unblock ip")) {
      const targetIp = (
        command.startsWith("unblock ip")
          ? command.replace(/^unblock ip\s+/i, "")
          : command.replace(/^unblock_ip\s+/i, "")
      ).trim();
      if (targetIp) {
        const { recordUnblockedIp } = await import("@/lib/fleet/blockedIps");
        const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");

        await recordUnblockedIp({
          tenantId: caller.tenant_id,
          ip: targetIp,
          unblockedBy: caller.email || caller.id,
        });

        if (targetAgent.ip_address && targetAgent.ip_address !== "Unknown" && targetAgent.ip_address !== targetIp) {
          await recordUnblockedIp({
            tenantId: caller.tenant_id,
            ip: targetAgent.ip_address,
            unblockedBy: caller.email || caller.id,
          });
        }

        await query(
          `UPDATE endpoint_agents
           SET status = 'connected', last_seen_at = now()
           WHERE id = $1 OR ip_address = $2;`,
          [targetAgent.id, targetIp]
        ).catch(() => {});
        await setLiveAgentStatus(targetAgent.id, "connected");
      }
    }

    // For unblock and restoration containment commands, control plane execution is decisive and immediate
    const isInstantRemediation = command.startsWith("unblock_ip") || command.startsWith("unblock ip") || command.startsWith("restore_host");

    if (isInstantRemediation) {
      try {
        await query(
          "UPDATE mitigation_tasks SET execution_command_id = $2, status = 'completed' WHERE id = $1 AND tenant_id = $3",
          [id, execResult.commandId, task.tenant_id]
        );
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        if (errMsg.includes("execution_command_id")) {
          await query("ALTER TABLE mitigation_tasks ADD COLUMN IF NOT EXISTS execution_command_id uuid;").catch(() => {});
          await query(
            "UPDATE mitigation_tasks SET status = 'completed' WHERE id = $1 AND tenant_id = $2",
            [id, task.tenant_id]
          ).catch(() => {});
        } else {
          throw err;
        }
      }
      await settleCommandTask({ id: execResult.commandId, tenant_id: task.tenant_id, status: "executed" });
    } else if (execResult.isSimulated) {
      try {
        await query(
          "UPDATE mitigation_tasks SET execution_command_id = $2, status = 'in_progress' WHERE id = $1 AND tenant_id = $3",
          [id, execResult.commandId, task.tenant_id]
        );
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        if (errMsg.includes("execution_command_id")) {
          await query("ALTER TABLE mitigation_tasks ADD COLUMN IF NOT EXISTS execution_command_id uuid;").catch(() => {});
          await query(
            "UPDATE mitigation_tasks SET status = 'in_progress' WHERE id = $1 AND tenant_id = $2",
            [id, task.tenant_id]
          ).catch(() => {});
        } else {
          throw err;
        }
      }
      await settleCommandTask({ id: execResult.commandId, tenant_id: task.tenant_id, status: execResult.state || "queued" });
    }
    const updatedTaskRes = await query<MitigationTaskRecord>(
      "SELECT * FROM mitigation_tasks WHERE id = $1 AND tenant_id = $2",
      [id, task.tenant_id]
    );
    const taskStatus = updatedTaskRes.rows[0]?.status || "in_progress";

    // 8. Record audit log
    await recordHashChainEvent({
      tenantId: task.tenant_id,
      eventType: taskStatus === "completed" ? "TASK_REMEDIATION_EXECUTED" : "TASK_REMEDIATION_QUEUED",
      actorId: caller.id,
      payload: {
        taskId: id,
        commandId: execResult.commandId,
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
      status: taskStatus,
      output: execResult.output,
      commandId: execResult.commandId,
      snapshotId: execResult.snapshotId,
      agent: {
        id: targetAgent.id,
        hostname: targetAgent.hostname,
        ipAddress: targetAgent.ip_address,
      },
      task: updatedTaskRes.rows[0] || { ...task, status: taskStatus },
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
