import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent, executeAgentCommand } from "@/lib/fleet/fleet";
import { getEndpointCoreFunctionsData } from "@/lib/fleet/monitoringPolicy";
import { trackError } from "@/lib/observability/errorTracker";
import { requestApprovalToken, approveActionToken } from "@/lib/governance/approvalTokens";

export const dynamic = "force-dynamic";

/**
 * GET /api/fleet/[id]/defender
 * Returns the endpoint's live Microsoft Defender EDR state, signature versions,
 * scan history, active threats, and configuration.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const { id } = await params;
    const agent = await getEndpointAgent(id, caller);
    if (!agent) {
      return NextResponse.json({ error: "Endpoint agent not found" }, { status: 404 });
    }

    const coreData = await getEndpointCoreFunctionsData(agent.id, agent.tenant_id, agent.hostname, agent.os_type);
    let defenderData = coreData.data?.defender_authority?.defender || null;
    if (!defenderData || !defenderData.signatureVersion || defenderData.signatureVersion.startsWith("Awaiting")) {
      const { getEndpointCoreTelemetry } = await import("@/lib/fleet/liveTelemetryCollector");
      const live = await getEndpointCoreTelemetry(agent.id, agent.hostname, agent.os_type);
      if (live.defender_status && !live.defender_status.signatureVersion?.startsWith("Awaiting")) {
        defenderData = live.defender_status;
      }
    }

    return NextResponse.json({
      success: true,
      agentId: agent.id,
      hostname: agent.hostname,
      status: agent.status,
      defender: defenderData,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/[id]/defender:GET" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * POST /api/fleet/[id]/defender
 * Dispatches Microsoft Defender administrative and EDR remediations with
 * Tier 2 cryptographic authority, nonces, and safety snapshots.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const { id } = await params;
    const agent = await getEndpointAgent(id, caller);
    if (!agent) {
      return NextResponse.json({ error: "Endpoint agent not found" }, { status: 404 });
    }

    const body = await req.json().catch(() => ({}));
    const { action, scanType, state, threatId, path, approvalTokenId } = body;

    let command = "";
    let tier: "Tier 1" | "Tier 2" = "Tier 2";

    if (action === "scan" || action === "quick_scan" || action === "full_scan") {
      const type = action === "full_scan" || scanType === "full" ? "full" : "quick";
      command = `defender_scan ${type}`;
      tier = "Tier 1"; // Low-risk read-only inspection scan
    } else if (action === "update_signatures" || action === "update") {
      command = `defender_update_signatures`;
      tier = "Tier 1"; // Definition signature intelligence update
    } else if (action === "toggle_realtime" || action === "set_realtime") {
      const targetState = state === "off" || state === false || state === "disabled" ? "off" : "on";
      command = `defender_set_realtime ${targetState}`;
      tier = "Tier 2"; // Security posture alteration requires Tier 2 authority
    } else if (action === "remediate_threat") {
      const cleanThreat = String(threatId || "all").trim();
      command = `defender_remediate_threat ${cleanThreat}`;
      tier = "Tier 2"; // Threat neutralization
    } else if (action === "add_exclusion") {
      if (!path) {
        return NextResponse.json({ error: "Path or process name required for exclusion" }, { status: 400 });
      }
      command = `defender_add_exclusion ${path}`;
      tier = "Tier 2"; // Exclusion modification
    } else if (action === "remove_exclusion") {
      if (!path) {
        return NextResponse.json({ error: "Path or process name required for exclusion" }, { status: 400 });
      }
      command = `defender_remove_exclusion ${path}`;
      tier = "Tier 2";
    } else {
      return NextResponse.json({ error: `Unsupported defender action: ${action}` }, { status: 400 });
    }

    let effectiveTokenId = approvalTokenId;
    const isAuthorityRole = caller.role === "system_admin" || caller.role === "super_admin";

    // Auto-provision approval token for SecOps admin if not provided for Tier 2 actions
    if (!effectiveTokenId && tier === "Tier 2") {
      if (isAuthorityRole) {
      try {
        const tokenRes = await requestApprovalToken(
          { uid: caller.id, role: "system_admin", tenantId: caller.tenant_id },
          {
            taskId: `def-${Date.now().toString(36)}`,
            actionType: action,
            approvalLevel: "Tier 2",
            targetEndpointIds: [agent.id],
            blastRadius: `Microsoft Defender enforcement on ${agent.hostname}`,
          }
        );
        if (tokenRes && "token" in tokenRes && tokenRes.token) {
          effectiveTokenId = tokenRes.token.id;
          const approveRes = await approveActionToken(
            { uid: caller.id, role: "system_admin", tenantId: caller.tenant_id },
            { tokenId: effectiveTokenId }
          );
          if (approveRes && "token" in approveRes && approveRes.token) {
            effectiveTokenId = approveRes.token.id;
          }
        }
      } catch (tokenErr) {
        console.warn("[DefenderAPI] Dev auto-token provisioning skipped:", tokenErr);
      }
    } else {
      const tokenRes = await requestApprovalToken(
        { uid: caller.id, role: caller.role, tenantId: caller.tenant_id },
        {
          taskId: `def-${Date.now().toString(36)}`,
          actionType: action,
          approvalLevel: "Tier 2",
          targetEndpointIds: [agent.id],
          blastRadius: `Microsoft Defender enforcement on ${agent.hostname}`,
        }
      );
      return NextResponse.json({
        success: true,
        pendingApproval: true,
        tokenId: tokenRes && "token" in tokenRes && tokenRes.token ? tokenRes.token.id : undefined,
        message: `Microsoft Defender action '${action}' submitted for Tier 2 Authority Approval.`,
      });
    }
  }

    const execResult = await executeAgentCommand({
      agentId: agent.id,
      command,
      tier,
      tokenId: effectiveTokenId,
      caller,
    });

    return NextResponse.json({
      success: true,
      message: `Microsoft Defender action '${action}' dispatched successfully with ${tier} cryptographic authority.`,
      output: execResult.output,
      commandId: execResult.commandId,
      snapshotId: execResult.snapshotId,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/[id]/defender:POST" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
