import "server-only";
import { query } from "@/lib/db";
import { canAccess } from "@/lib/permissions";
import type { ChatSession } from "@/lib/auth/session";
import { classifyResponseTier, calculateModelConfidence, type AutonomyTier } from "./autonomyTier";
import { dispatchSecurityNotification } from "@/lib/notifications/dispatcher";

export interface ApprovalTokenRecord {
  id: string;
  tenant_id: string;
  task_id: string;
  action_type: string;
  tier: AutonomyTier;
  status: "pending" | "approved" | "rejected" | "expired";
  requested_by: string;
  approved_by: string | null;
  rejection_reason?: string | null;
  blast_radius: string;
  model_confidence: number;
  expires_at: string;
  created_at: string;
  updated_at: string;
  task_title?: string;
  task_description?: string;
}

// In-memory mock store for offline / dev fallback
const MOCK_APPROVAL_TOKENS: Record<string, ApprovalTokenRecord> = {
  "tok11111-1111-1111-1111-111111111111": {
    id: "tok11111-1111-1111-1111-111111111111",
    tenant_id: "acme-tenant",
    task_id: "t1111111-1111-1111-1111-111111111111",
    action_type: "isolate_host",
    tier: "Tier 2",
    status: "pending",
    requested_by: "dev-analyst",
    approved_by: null,
    blast_radius: "Workstation FIN-WS-042 (Finance Subnet)",
    model_confidence: 0.96,
    expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
    created_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    task_title: "Isolate affected host FIN-WS-042",
    task_description: "Quarantine endpoint network interface to halt lateral movement toward database server",
  },
};

/**
 * Requests an approval token for a mitigation task.
 * Never executes automatically — creates a pending token awaiting human sign-off.
 */
export async function requestApprovalToken(
  session: ChatSession,
  args: {
    taskId: string;
    actionType?: string;
    blastRadius?: string;
    cveScore?: number;
  }
) {
  if (!args.taskId) return { error: "missing_task_id" };

  const action = args.actionType || "remediate_task";
  const classification = classifyResponseTier(action, { cveScore: args.cveScore });
  const tier = classification.tier;
  const confidence = calculateModelConfidence(tier);
  const tokenId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const blastRadius = args.blastRadius || "Target Host / Subnet";

  try {
    const insertResult = await query<ApprovalTokenRecord>(
      `INSERT INTO approval_tokens (
        id, tenant_id, task_id, action_type, tier, status, requested_by, blast_radius, model_confidence, expires_at, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9, now(), now())
      RETURNING *`,
      [tokenId, session.tenantId, args.taskId, action, tier, session.uid, blastRadius, confidence, expiresAt]
    );

    // Audit write
    await query(
      `INSERT INTO approval_audit_log (token_id, tenant_id, actor_id, action, details, created_at)
       VALUES ($1, $2, $3, 'token_requested', $4, now())`,
      [tokenId, session.tenantId, session.uid, `Requested ${tier} approval for task ${args.taskId}`]
    );

    const tokenRecord = insertResult.rows[0];

    // Dispatch real-time alert to Slack/Teams/SIEM
    dispatchSecurityNotification({
      type: "approval_required",
      tenantId: session.tenantId,
      title: `Human Sign-Off Required: [${tier}] ${action}`,
      description: `Task ${args.taskId} requires authorization before execution. Blast radius: ${blastRadius}.`,
      severity: tier === "Tier 3" ? "critical" : "high",
      actionUrl: `http://localhost:3000/dashboard/tasks`,
      metadata: { tokenId, taskId: args.taskId, tier },
    }).catch(() => {});

    return { token: tokenRecord };
  } catch {
    // Dev fallback if database is offline
    const mockToken: ApprovalTokenRecord = {
      id: tokenId,
      tenant_id: session.tenantId,
      task_id: args.taskId,
      action_type: action,
      tier,
      status: "pending",
      requested_by: session.uid,
      approved_by: null,
      blast_radius: blastRadius,
      model_confidence: confidence,
      expires_at: expiresAt,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      task_title: `Security Action: ${action}`,
    };
    MOCK_APPROVAL_TOKENS[tokenId] = mockToken;

    dispatchSecurityNotification({
      type: "approval_required",
      tenantId: session.tenantId,
      title: `Human Sign-Off Required: [${tier}] ${action}`,
      description: `Task ${args.taskId} requires authorization before execution. Blast radius: ${blastRadius}.`,
      severity: tier === "Tier 3" ? "critical" : "high",
      actionUrl: `http://localhost:3000/dashboard/tasks`,
      metadata: { tokenId, taskId: args.taskId, tier },
    }).catch(() => {});

    return { token: mockToken };
  }
}

/**
 * Approves an action token with strictly enforced Separation-of-Duties.
 * Requested by != Approved by is guaranteed.
 */
export async function approveActionToken(
  session: ChatSession,
  args: { tokenId: string }
) {
  if (!args.tokenId) return { error: "missing_token_id" };

  try {
    // 1. Fetch token with tenant check
    const tenantScope = canAccess(session.role, "VIEW_CROSS_TENANT") ? "" : "AND tenant_id = $2";
    const params = canAccess(session.role, "VIEW_CROSS_TENANT")
      ? [args.tokenId]
      : [args.tokenId, session.tenantId];

    const tokenRes = await query<ApprovalTokenRecord>(
      `SELECT * FROM approval_tokens WHERE id = $1 ${tenantScope} LIMIT 1`,
      params
    );

    const token = tokenRes.rows[0];
    if (!token) return { error: "not_found" }; // 404 anti-enumeration

    // 2. Separation of Duties enforcement: Requester CANNOT approve their own action
    if (token.requested_by === session.uid) {
      return {
        error: "separation_of_duties_violation",
        message: "Separation of duties violation: you cannot approve your own action request.",
      };
    }

    // 3. Anti-Replay check
    if (token.status !== "pending") {
      return {
        error: "token_already_processed",
        message: `Token has already been ${token.status}.`,
      };
    }

    // 4. Expiration check
    if (new Date(token.expires_at) < new Date()) {
      await query("UPDATE approval_tokens SET status = 'expired', updated_at = now() WHERE id = $1", [token.id]);
      return {
        error: "token_expired",
        message: "Approval token has expired.",
      };
    }

    // 5. Update token to approved
    const updated = await query<ApprovalTokenRecord>(
      `UPDATE approval_tokens
       SET status = 'approved', approved_by = $1, updated_at = now()
       WHERE id = $2
       RETURNING *`,
      [session.uid, token.id]
    );

    // 6. Update linked task status
    if (token.task_id) {
      await query("UPDATE mitigation_tasks SET status = 'approved' WHERE id = $1", [token.task_id]);
    }

    // 7. Write immutable audit log
    await query(
      `INSERT INTO approval_audit_log (token_id, tenant_id, actor_id, action, details, created_at)
       VALUES ($1, $2, $3, 'token_approved', $4, now())`,
      [token.id, token.tenant_id, session.uid, `Approved by ${session.uid} (Role: ${session.role})`]
    );

    return {
      success: true,
      token: updated.rows[0],
      executionStatus: "simulated_containment_successful",
      message: `Action '${token.action_type}' approved and dispatched under ${token.tier} governance.`,
    };
  } catch {
    // Dev fallback if database is offline
    const token = MOCK_APPROVAL_TOKENS[args.tokenId];
    if (!token) return { error: "not_found" };
    if (!canAccess(session.role, "VIEW_CROSS_TENANT") && token.tenant_id !== session.tenantId) {
      return { error: "not_found" }; // 404 anti-enumeration
    }

    // Separation of Duties check in mock mode
    if (token.requested_by === session.uid) {
      return {
        error: "separation_of_duties_violation",
        message: "Separation of duties violation: you cannot approve your own action request.",
      };
    }

    if (token.status !== "pending") {
      return {
        error: "token_already_processed",
        message: `Token has already been ${token.status}.`,
      };
    }

    if (new Date(token.expires_at) < new Date()) {
      token.status = "expired";
      return { error: "token_expired", message: "Approval token has expired." };
    }

    token.status = "approved";
    token.approved_by = session.uid;
    token.updated_at = new Date().toISOString();

    return {
      success: true,
      token,
      executionStatus: "simulated_containment_successful",
      message: `Action '${token.action_type}' approved and dispatched under ${token.tier} governance.`,
    };
  }
}

/**
 * Rejects an action token with an audit rationale.
 */
export async function rejectActionToken(
  session: ChatSession,
  args: { tokenId: string; reason?: string }
) {
  if (!args.tokenId) return { error: "missing_token_id" };

  try {
    const tenantScope = canAccess(session.role, "VIEW_CROSS_TENANT") ? "" : "AND tenant_id = $2";
    const params = canAccess(session.role, "VIEW_CROSS_TENANT")
      ? [args.tokenId]
      : [args.tokenId, session.tenantId];

    const tokenRes = await query<ApprovalTokenRecord>(
      `SELECT * FROM approval_tokens WHERE id = $1 ${tenantScope} LIMIT 1`,
      params
    );
    const token = tokenRes.rows[0];
    if (!token) return { error: "not_found" };

    if (token.status !== "pending") {
      return { error: "token_already_processed", message: `Token has already been ${token.status}.` };
    }

    const updated = await query<ApprovalTokenRecord>(
      `UPDATE approval_tokens
       SET status = 'rejected', approved_by = $1, rejection_reason = $2, updated_at = now()
       WHERE id = $3
       RETURNING *`,
      [session.uid, args.reason || "Rejected by analyst", token.id]
    );

    if (token.task_id) {
      await query("UPDATE mitigation_tasks SET status = 'rejected' WHERE id = $1", [token.task_id]);
    }

    await query(
      `INSERT INTO approval_audit_log (token_id, tenant_id, actor_id, action, details, created_at)
       VALUES ($1, $2, $3, 'token_rejected', $4, now())`,
      [token.id, token.tenant_id, session.uid, `Rejected: ${args.reason || "No reason specified"}`]
    );

    return { success: true, token: updated.rows[0] };
  } catch {
    const token = MOCK_APPROVAL_TOKENS[args.tokenId];
    if (!token) return { error: "not_found" };
    if (!canAccess(session.role, "VIEW_CROSS_TENANT") && token.tenant_id !== session.tenantId) {
      return { error: "not_found" };
    }
    if (token.status !== "pending") {
      return { error: "token_already_processed", message: `Token has already been ${token.status}.` };
    }
    token.status = "rejected";
    token.approved_by = session.uid;
    token.rejection_reason = args.reason || "Rejected by analyst";
    token.updated_at = new Date().toISOString();
    return { success: true, token };
  }
}

/**
 * Lists approval tokens scoped strictly to caller's tenant.
 */
export async function listApprovalTokens(
  session: ChatSession,
  args: { status?: string; taskId?: string } = {}
) {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (!canAccess(session.role, "VIEW_CROSS_TENANT")) {
    params.push(session.tenantId);
    conditions.push(`t.tenant_id = $${params.length}`);
  }

  if (args.status) {
    params.push(args.status);
    conditions.push(`t.status = $${params.length}`);
  }

  if (args.taskId) {
    params.push(args.taskId);
    conditions.push(`t.task_id = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  try {
    const result = await query<ApprovalTokenRecord>(
      `SELECT t.*, mt.title as task_title, mt.description as task_description
       FROM approval_tokens t
       LEFT JOIN mitigation_tasks mt ON mt.id = t.task_id
       ${where}
       ORDER BY t.created_at DESC`,
      params
    );
    return { tokens: result.rows };
  } catch {
    // Dev fallback if database is offline
    const list = Object.values(MOCK_APPROVAL_TOKENS).filter((t) => {
      if (!canAccess(session.role, "VIEW_CROSS_TENANT") && t.tenant_id !== session.tenantId) {
        return false;
      }
      if (args.status && t.status !== args.status) return false;
      if (args.taskId && t.task_id !== args.taskId) return false;
      return true;
    });
    return { tokens: list };
  }
}

/**
 * Retrieves a single approval token with tenant boundary and anti-enumeration.
 */
export async function getApprovalToken(
  tokenId: string,
  caller: { role: string; tenant_id?: string; tenantId?: string }
): Promise<ApprovalTokenRecord | null> {
  const role = caller.role;
  const tenantId = caller.tenant_id || caller.tenantId || "";

  try {
    const tenantScope = canAccess(role, "VIEW_CROSS_TENANT") ? "" : "AND tenant_id = $2";
    const params = canAccess(role, "VIEW_CROSS_TENANT") ? [tokenId] : [tokenId, tenantId];

    const result = await query<ApprovalTokenRecord>(
      `SELECT * FROM approval_tokens WHERE id = $1 ${tenantScope} LIMIT 1`,
      params
    );
    if (result && result.rows.length > 0) {
      return result.rows[0];
    }
  } catch {
    // mock fallback
  }

  const token = MOCK_APPROVAL_TOKENS[tokenId];
  if (!token) return null;
  if (!canAccess(role, "VIEW_CROSS_TENANT") && token.tenant_id !== tenantId) {
    return null; // Anti-enumeration 404
  }
  return token;
}

