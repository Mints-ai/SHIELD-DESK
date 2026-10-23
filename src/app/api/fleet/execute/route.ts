import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { executeAgentCommand } from "@/lib/fleet/fleet";
import { setLiveAgentStatus } from "@/lib/fleet/liveTelemetry";
import { trackError } from "@/lib/observability/errorTracker";
import { requestApprovalToken, approveActionToken } from "@/lib/governance/approvalTokens";
import { blockIp, unblockIp } from "@/lib/alerts/threatAlertStore";
import { query } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const { agentId, command, tier = "Tier 1", approvalTokenId } = body;

    if (!agentId || typeof agentId !== "string") {
      return NextResponse.json({ error: "agentId is required" }, { status: 400 });
    }

    if (!command || typeof command !== "string") {
      return NextResponse.json({ error: "command is required" }, { status: 400 });
    }

    // Parameter & containment state validation for IP block/unblock actions
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

      const { validateIpAddress } = await import("@/lib/utils/ipValidation");
      const val = validateIpAddress(targetIp);
      if (!val.valid) {
        return NextResponse.json(
          { error: `INVALID_IP_ADDRESS: ${val.error}` },
          { status: 400 }
        );
      }

      let resolvedAgentUuid = agentId;
      try {
        const agentLookup = await query<{ id: string }>(
          `SELECT id FROM endpoint_agents WHERE id::text = $1 OR hostname = $1 LIMIT 1`,
          [agentId]
        );
        if (agentLookup.rows.length > 0) {
          resolvedAgentUuid = agentLookup.rows[0].id;
        }
      } catch {}

      const { checkIsIpCurrentlyBlocked, isUnblockPendingForIp } = await import("@/lib/fleet/fleet");
      const isCurrentlyBlocked = await checkIsIpCurrentlyBlocked(targetIp, caller.tenant_id, approvalTokenId);

      if (isUnblock) {
        const pendingCheck = await isUnblockPendingForIp(targetIp, caller.tenant_id);
        if (pendingCheck.pending && !approvalTokenId) {
          return NextResponse.json(
            {
              success: false,
              error: `An unblock request for IP ${targetIp} is already awaiting authorization on the Task Board${pendingCheck.taskId ? ` (Task #${pendingCheck.taskId})` : ""}.`,
            },
            { status: 400 }
          );
        }

        if (!isCurrentlyBlocked) {
          // IP is already unblocked, but ensure the endpoint is reconnected and admin locks are cleared
          const { setLiveAgentStatus, adminDisconnectedAgents } = await import("@/lib/fleet/liveTelemetry");
          const { getEndpointAgent } = await import("@/lib/fleet/fleet");
          const agent = await getEndpointAgent(agentId, caller);

          await query(
            `UPDATE endpoint_agents
             SET status = 'connected', last_seen_at = now()
             WHERE (id::text = $1 OR ip_address = $2 OR hostname = $3)
               AND (tenant_id = $4 OR $4 = 'mints-global');`,
            [agent?.id || agentId, targetIp, agent?.hostname || agentId, caller.tenant_id]
          ).catch(() => {});

          await setLiveAgentStatus(agentId, "connected");
          if (agent?.id) adminDisconnectedAgents.delete(agent.id);
          if (agent?.hostname) adminDisconnectedAgents.delete(agent.hostname);
          adminDisconnectedAgents.delete(agentId);

          const rejId = crypto.randomUUID();
          const rejMsg = `The IP address ${targetIp} is not currently blocked. Endpoint status has been refreshed to connected.`;
          await query(
            `INSERT INTO agent_command_logs (id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at)
             VALUES ($1, $2, $3, $4, $5, 'succeeded', $6, $7, now())`,
            [rejId, resolvedAgentUuid, caller.tenant_id, command, tier, rejMsg, caller.id]
          ).catch(() => {});

          return NextResponse.json({
            success: true,
            output: rejMsg,
            commandId: rejId,
            status: "connected",
          });
        }
      }

      if (!isUnblock && isCurrentlyBlocked && !approvalTokenId) {
        let hasAgentBlocked = false;
        try {
          const { rows: agentBlockCheck } = await query<{ count: string }>(
            `SELECT COUNT(*) as count FROM agent_command_logs
             WHERE agent_id = $1 AND (command ILIKE $2 OR command ILIKE $3) AND status IN ('succeeded', 'verified')`,
            [resolvedAgentUuid, `block_ip ${targetIp}%`, `block ip ${targetIp}%`]
          );
          hasAgentBlocked = parseInt(agentBlockCheck[0]?.count || "0", 10) > 0;
        } catch {}

        if (hasAgentBlocked) {
          const rejId = crypto.randomUUID();
          const rejMsg = `The IP address ${targetIp} is already blocked on this endpoint.`;
          await query(
            `INSERT INTO agent_command_logs (id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at)
             VALUES ($1, $2, $3, $4, $5, 'failed', $6, $7, now())`,
            [rejId, resolvedAgentUuid, caller.tenant_id, command, tier, rejMsg, caller.id]
          ).catch(() => {});

          return NextResponse.json(
            { success: false, error: rejMsg, commandId: rejId },
            { status: 400 }
          );
        }
      }
    }

    let effectiveTokenId = approvalTokenId;

    // Check if provided token is pending review
    if (effectiveTokenId) {
      try {
        const tokenCheck = await query<{ id: string; task_id: string; status: string; tier: string }>(
          "SELECT id, task_id, status, tier FROM approval_tokens WHERE id = $1 LIMIT 1",
          [effectiveTokenId]
        );
        if (tokenCheck.rows.length > 0) {
          const tok = tokenCheck.rows[0];
          if (tok.status === "pending") {
            return NextResponse.json({
              success: true,
              pendingApproval: true,
              requiresApproval: true,
              taskId: tok.task_id,
              tokenId: tok.id,
              command,
              tier: tok.tier || tier,
              message: `Approval request is currently PENDING review. Mitigation Task #${String(tok.task_id).slice(0, 8)} is visible on the Task Board awaiting Super Admin authorization.`,
            });
          }
          if (tok.status === "rejected") {
            return NextResponse.json(
              { error: "APPROVAL_TOKEN_REJECTED: This token was rejected by security governance." },
              { status: 403 }
            );
          }
        }
      } catch {
        // Non-blocking query check
      }
    }

    // When Tier 2 or Tier 3 action is dispatched without an approved token,
    // create a real mitigation task and pending approval token visible on the Task Board.
    if ((tier === "Tier 2" || tier === "Tier 3") && !effectiveTokenId) {
      // 1. Resolve Endpoint Details
      const { getEndpointAgent } = await import("@/lib/fleet/fleet");
      const agent = await getEndpointAgent(agentId, caller);
      const hostname = agent?.hostname || agentId;
      const ip = agent?.ip_address || "";

      // 2. Optional Plan Association (Default to null / Standalone unless explicitly provided)
      let planId: string | null = (body.planId && typeof body.planId === "string" && body.planId.trim())
        ? body.planId.trim()
        : null;

      if (!planId) {
        try {
          const activePlan = await query<{ id: string }>(
            "SELECT id FROM mitigation_plans WHERE tenant_id = $1 AND status IN ('active', 'draft') ORDER BY created_at DESC LIMIT 1",
            [caller.tenant_id]
          );
          if (activePlan.rows.length > 0) {
            planId = activePlan.rows[0].id;
          }
        } catch {
          // Non-blocking
        }
      }

      // 3. Ensure caller exists in users table to satisfy foreign keys
      try {
        const userCheck = await query("SELECT id FROM users WHERE id = $1 LIMIT 1", [caller.id]);
        if (userCheck.rows.length === 0) {
          await query(
            "INSERT INTO users (id, tenant_id, role, email) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
            [caller.id, caller.tenant_id, caller.role, caller.email || `${caller.id}@shielddesk.local`]
          );
        }
      } catch {
        // Non-blocking
      }

      // Ensure plan_id is nullable in DB for standalone tasks
      await query("ALTER TABLE mitigation_tasks ALTER COLUMN plan_id DROP NOT NULL;").catch(() => {});

      // 4. Create Mitigation Task
      const taskId = crypto.randomUUID();
      const taskTitle = `Tier 2 Containment: ${command} on ${hostname}`;
      const blastRadius = `Endpoint ${hostname}${ip ? ` (${ip})` : ""}`;

      await query(
        `INSERT INTO mitigation_tasks (
           id, plan_id, tenant_id, horizon, title, description, tier, status, blast_radius, assigned_to, created_at
         ) VALUES ($1, $2, $3, 'immediate', $4, $5, $6, 'pending', $7, $8, now())`,
        [
          taskId,
          planId,
          caller.tenant_id,
          taskTitle,
          command,
          tier,
          blastRadius,
          caller.id,
        ]
      );

      // 5. Request Governance Approval Token
      const tokenRes = await requestApprovalToken(
        {
          uid: caller.id,
          role: caller.role,
          tenantId: caller.tenant_id,
          email: caller.email,
        },
        {
          taskId,
          actionType: command.split(" ")[0],
          blastRadius,
          tier,
          targetEndpointIds: [agentId, hostname, ip].filter(Boolean) as string[],
          command,
          approvalLevel: tier,
        }
      );

      const tokenId = tokenRes && "token" in tokenRes && tokenRes.token ? tokenRes.token.id : null;

      // 6. Write pending entry to agent_command_logs
      const logId = crypto.randomUUID();
      await query(
        `INSERT INTO agent_command_logs (
           id, agent_id, tenant_id, command, tier, token_id, status, output, executed_by, executed_at
         ) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, now())`,
        [
          logId,
          agentId,
          caller.tenant_id,
          command,
          tier,
          tokenId,
          `[APPROVAL PENDING] Action '${command}' is ${tier} and requires Super Admin sign-off. Mitigation Task #${taskId.slice(0, 8)} created on Task Board awaiting authorization.`,
          caller.id,
        ]
      ).catch(() => {});

      // 7. Return immediate pending response
      return NextResponse.json({
        success: true,
        pendingApproval: true,
        requiresApproval: true,
        taskId,
        tokenId,
        command,
        tier,
        commandId: logId,
        message: `Action '${command}' requires human sign-off (${tier}). Mitigation Task #${taskId.slice(0, 8)} is now visible on the Task Board awaiting Super Admin authorization.`,
      });
    }

    const result = await executeAgentCommand({
      agentId,
      command,
      tier,
      tokenId: effectiveTokenId,
      caller,
    });

    // Update real-time fleet state based on command executed
    if (command.startsWith("isolate_host")) {
      const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");
      const { recordBlockedIp } = await import("@/lib/fleet/blockedIps");
      const { getEndpointAgent } = await import("@/lib/fleet/fleet");
      const agent = await getEndpointAgent(agentId, caller);

      await setLiveAgentStatus(agentId, "isolated", result.snapshotId);
      await setLiveAgentStatus(agentId, "disconnected", result.snapshotId);

      // Enforce edge containment for this endpoint's registered IP address
      if (agent?.ip_address && agent.ip_address !== "Unknown") {
        await recordBlockedIp({
          tenantId: caller.tenant_id,
          ip: agent.ip_address,
          agentId,
          hostname: agent.hostname || agentId,
          reason: `Tier 2 host isolation executed by ${caller.email || caller.id}`,
          tier,
          blockedBy: caller.email || caller.id,
        });
      }

      await query(
        `UPDATE endpoint_agents
         SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
         WHERE id = $1;`,
        [agentId]
      ).catch(() => {});

      const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
      for (const a of MOCK_ENDPOINT_AGENTS) {
        if (a.id === agentId) {
          a.status = "disconnected";
          a.cpu_usage = 0;
          a.memory_usage = 0;
          a.eps = 0;
        }
      }

      result.output =
        `[ISOLATION ACTIVE] Host ${agent?.hostname || agentId} is completely isolated and disconnected.\n` +
        `• Network interfaces quarantined; all inbound and outbound host traffic is terminated.\n` +
        (agent?.ip_address ? `• IP ${agent.ip_address} added to Edge Containment registry (all web/API access terminated).\n` : "") +
        `• Baseline safety snapshot ${result.snapshotId || "registered"} saved for rollback.\n\n` +
        `To restore connectivity, dispatch:\n  restore_host`;
    } else if (command.startsWith("restore_host")) {
      const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");
      const { recordUnblockedIp } = await import("@/lib/fleet/blockedIps");
      const { getEndpointAgent } = await import("@/lib/fleet/fleet");
      const agent = await getEndpointAgent(agentId, caller);

      await setLiveAgentStatus(agentId, "connected");

      if (agent?.ip_address && agent.ip_address !== "Unknown") {
        await recordUnblockedIp({
          tenantId: caller.tenant_id,
          ip: agent.ip_address,
          unblockedBy: caller.email || caller.id,
        });
      }

      await query(
        `UPDATE endpoint_agents
         SET status = 'connected', last_seen_at = now()
         WHERE id = $1;`,
        [agentId]
      ).catch(() => {});

      const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
      for (const a of MOCK_ENDPOINT_AGENTS) {
        if (a.id === agentId) {
          a.status = "connected";
        }
      }

      result.output =
        `[ISOLATION LIFTED] Host ${agent?.hostname || agentId} network interfaces restored to operational baseline.\n` +
        `Edge containment rules removed. Telemetry streaming active.`;
    } else if (command.startsWith("take_safety_snapshot") && result.snapshotId) {
      await setLiveAgentStatus(agentId, "connected", result.snapshotId);
    } else if (command.startsWith("block_ip") || command.startsWith("block ip")) {
      const targetIp = (
        command.startsWith("block ip")
          ? command.replace(/^block ip\s+/i, "")
          : command.replace(/^block_ip\s+/i, "")
      ).trim();

      if (targetIp) {
        const { recordBlockedIp } = await import("@/lib/fleet/blockedIps");
        const { getEndpointAgent } = await import("@/lib/fleet/fleet");
        const agent = await getEndpointAgent(agentId, caller);

        // 1. Enforce IP containment and record in persistent registry
        await recordBlockedIp({
          tenantId: caller.tenant_id,
          ip: targetIp,
          agentId,
          hostname: agent?.hostname || agentId,
          reason: `Fleet containment executed by ${caller.email || caller.id} on host ${agent?.hostname || agentId}`,
          tier,
          blockedBy: caller.email || caller.id,
        });

        // 2. Disconnect the endpoint ONLY if target IP matches this agent's own registered IP, or is loopback
        const isTargetHostItself =
          Boolean(agent?.ip_address && agent.ip_address !== "Unknown" && agent.ip_address === targetIp) ||
          targetIp === "127.0.0.1";

        if (isTargetHostItself) {
          await query(
            `UPDATE endpoint_agents
             SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
             WHERE id = $1;`,
            [agentId]
          ).catch(() => {});

          await setLiveAgentStatus(agentId, "disconnected", result.snapshotId);

          const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
          for (const a of MOCK_ENDPOINT_AGENTS) {
            if (a.id === agentId) {
              a.status = "disconnected";
              a.cpu_usage = 0;
              a.memory_usage = 0;
              a.eps = 0;
            }
          }
        }

        // 3. Clear, actionable operator instructions in output
        result.output =
          `[CONTAINMENT ACTIVE] Local firewall rule inserted: DROP all traffic to/from ${targetIp}. Safety snapshot ${result.snapshotId || "registered"} saved on host ${agent?.hostname || agentId}.\n` +
          (isTargetHostItself
            ? `Endpoint ${agent?.hostname || agentId} is now contained and completely disconnected from the fleet.\n\n`
            : `Host ${agent?.hostname || agentId} firewall active. IP ${targetIp} is blocked.\n\n`) +
          `WHAT TO DO NEXT:\n` +
          `• IP ${targetIp} is recorded in the Fleet Blocked IPs ledger.\n` +
          `• To restore connectivity, click 'Unblock' in the Blocked IPs panel or dispatch:\n` +
          `  unblock_ip ${targetIp}`;
      }
    } else if (command.startsWith("unblock_ip") || command.startsWith("unblock ip")) {
      const targetIp = (
        command.startsWith("unblock ip")
          ? command.replace(/^unblock ip\s+/i, "")
          : command.replace(/^unblock_ip\s+/i, "")
      ).trim();

      if (targetIp) {
        const { recordUnblockedIp } = await import("@/lib/fleet/blockedIps");
        const { getEndpointAgent } = await import("@/lib/fleet/fleet");
        const agent = await getEndpointAgent(agentId, caller);

        // 1. Lift IP containment from persistent registry & threatAlertStore
        await recordUnblockedIp({
          tenantId: caller.tenant_id,
          ip: targetIp,
          unblockedBy: caller.email || caller.id,
        });

        // 2. Restore connected status in PostgreSQL for target agent & any endpoint with targetIp
        await query(
          `UPDATE endpoint_agents
           SET status = 'connected', last_seen_at = now()
           WHERE (id::text = $1 OR ip_address = $2 OR hostname = $3)
             AND (tenant_id = $4 OR $4 = 'mints-global');`,
          [agent?.id || agentId, targetIp, agent?.hostname || agentId, caller.tenant_id]
        ).catch(() => {});

        // 3. Mark live agent status as connected & clear admin disconnected locks
        const { setLiveAgentStatus, adminDisconnectedAgents } = await import("@/lib/fleet/liveTelemetry");
        await setLiveAgentStatus(agentId, "connected");
        if (agent?.id) adminDisconnectedAgents.delete(agent.id);
        if (agent?.hostname) adminDisconnectedAgents.delete(agent.hostname);
        adminDisconnectedAgents.delete(agentId);

        try {
          const { rows: reconnectedAgents } = await query<{ id: string; hostname: string }>(
            `SELECT id, hostname FROM endpoint_agents WHERE ip_address = $1`,
            [targetIp]
          );
          for (const a of reconnectedAgents) {
            adminDisconnectedAgents.delete(a.id);
            if (a.hostname) adminDisconnectedAgents.delete(a.hostname);
          }
        } catch {}

        // 4. Update in-memory fallback store
        const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
        for (const a of MOCK_ENDPOINT_AGENTS) {
          if (
            a.id === (agent?.id || agentId) ||
            a.hostname === (agent?.hostname || agentId)
          ) {
            a.status = "connected";
          }
        }

        // 5. Provide clear instructions in output
        result.output =
          `[CONTAINMENT LIFTED] Firewall drop rule removed for IP ${targetIp}.\n` +
          `Host ${agent?.hostname || agentId} connectivity restored.\n\n` +
          `IP ${targetIp} has been marked as unblocked in the Fleet Containment Ledger.\n` +
          `Endpoint agent will resume live telemetry streaming automatically on its next heartbeat.`;
      }
    }

    return NextResponse.json({
      success: true,
      commandId: result.commandId,
      output: result.output,
      tier: result.tier,
      snapshotId: result.snapshotId,
      state: result.state,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    if (msg.includes("AGENT_NOT_FOUND")) {
      return NextResponse.json({ error: "Endpoint agent not found" }, { status: 404 });
    }
    if (msg.includes("INVALID_IP_ADDRESS") || msg.includes("INVALID_PID")) {
      return NextResponse.json({ error: msg }, { status: 400 });
    }
    if (
      msg.includes("APPROVAL_TOKEN_REQUIRED") ||
      msg.includes("APPROVAL_TOKEN_NOT_APPROVED") ||
      msg.includes("APPROVAL_TOKEN_EXPIRED")
    ) {
      return NextResponse.json({ error: msg }, { status: 403 });
    }
    if (msg.includes("KILL_SWITCH_ACTIVE")) {
      return NextResponse.json({ error: msg }, { status: 423 });
    }
    if (msg.includes("BLAST_RADIUS_EXCEEDED")) {
      return NextResponse.json(
        {
          error: msg,
          code: "BLAST_RADIUS_EXCEEDED",
          downgraded_tier: "Tier 2",
          requires_approval: true,
        },
        { status: 429 }
      );
    }
    trackError(err, { endpoint: "/api/fleet/execute" });
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
