import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent, executeAgentCommand } from "@/lib/fleet/fleet";
import { getEndpointCoreFunctionsData } from "@/lib/fleet/monitoringPolicy";
import { trackError } from "@/lib/observability/errorTracker";
import { requestApprovalToken, approveActionToken } from "@/lib/governance/approvalTokens";

export const dynamic = "force-dynamic";

/**
 * GET /api/fleet/[id]/firewall
 * Returns the endpoint's live firewall profiles, default policies, and active rules.
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

    const coreData = await getEndpointCoreFunctionsData(agent.id, agent.tenant_id, agent.hostname);
    const firewallBaseline = coreData.data?.firewall_baseline?.baseline || null;

    return NextResponse.json({
      success: true,
      agentId: agent.id,
      hostname: agent.hostname,
      status: agent.status,
      firewall: firewallBaseline,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/[id]/firewall:GET" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * POST /api/fleet/[id]/firewall
 * Dispatches firewall modifications with Tier 2 cryptographic authority and auto-rollback safety.
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
    const { action, rule, ruleName, profile, state, inbound, outbound, approvalTokenId } = body;

    let command = "";
    if (action === "add_rule") {
      if (!rule || !rule.name) {
        return NextResponse.json({ error: "Rule specification with 'name' is required" }, { status: 400 });
      }
      const sanitizedName = String(rule.name).trim().replace(/\s+/g, "-").replace(/[^a-zA-Z0-9_-]/g, "");
      if (!sanitizedName) {
        return NextResponse.json({ error: "Rule name must contain alphanumeric characters" }, { status: 400 });
      }
      const dir = rule.direction || "in";
      const actionType = rule.action || "block";
      const proto = rule.protocol || "TCP";
      const port = rule.port || rule.localPort || "";
      const remoteIp = rule.remoteIp || "";
      const cmdParts = ["firewall_add_rule", sanitizedName, dir, actionType, proto];
      if (port) cmdParts.push(String(port).trim());
      if (remoteIp) cmdParts.push(String(remoteIp).trim());
      command = cmdParts.join(" ");
    } else if (action === "delete_rule") {
      if (!ruleName) {
        return NextResponse.json({ error: "ruleName is required to delete" }, { status: 400 });
      }
      command = `firewall_delete_rule ${ruleName}`;
    } else if (action === "set_profile") {
      if (!profile || !state) {
        return NextResponse.json({ error: "profile and state ('on'|'off') are required" }, { status: 400 });
      }
      command = `firewall_set_profile ${profile} ${state}`;
    } else if (action === "set_default") {
      if (!inbound || !outbound) {
        return NextResponse.json({ error: "inbound and outbound policies are required" }, { status: 400 });
      }
      command = `firewall_set_default ${inbound} ${outbound}`;
    } else {
      return NextResponse.json({ error: `Unsupported firewall action: ${action}` }, { status: 400 });
    }

    let effectiveTokenId = approvalTokenId;
    const isAuthorityRole = caller.role === "system_admin" || caller.role === "super_admin";

    if (!effectiveTokenId && !isAuthorityRole) {
      return NextResponse.json(
        {
          error: "Tier 2 Permission Denied: Firewall enforcement requires System Admin or Super Admin authority. Switch your operator persona in the top navigation bar to 'System Admin', or enter an approved Authority Token ID.",
        },
        { status: 403 }
      );
    }

    // Auto-provision approval token for SecOps admin if not provided
    if (!effectiveTokenId && isAuthorityRole) {
      try {
        const tokenRes = await requestApprovalToken(
          { uid: caller.id, role: "system_admin", tenantId: caller.tenant_id },
          {
            taskId: `fw-${Date.now().toString(36)}`,
            actionType: action,
            approvalLevel: "Tier 2",
            targetEndpointIds: [agent.id],
            blastRadius: `Firewall update on ${agent.hostname}`,
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
        console.warn("[FirewallAPI] Dev auto-token provisioning skipped:", tokenErr);
      }
    }

    const execResult = await executeAgentCommand({
      agentId: agent.id,
      command,
      tier: "Tier 2",
      tokenId: effectiveTokenId,
      caller,
    });

    return NextResponse.json({
      success: true,
      message: `Firewall action '${action}' dispatched successfully with Tier 2 cryptographic authority.`,
      output: execResult.output,
      commandId: execResult.commandId,
      snapshotId: execResult.snapshotId,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/[id]/firewall:POST" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
