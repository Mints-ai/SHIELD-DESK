import "server-only";
import { query } from "@/lib/db";
import { AIAgentIdentity } from "./types";

const IN_MEMORY_AGENTS: Map<string, AIAgentIdentity> = new Map();

// Default seed AI agents
const DEFAULT_AI_AGENT: AIAgentIdentity = {
  id: "ai-agent-triage-default",
  tenantId: "*",
  name: "ShieldDesk Automated Triage Advisor",
  role: "ai_agent",
  isAiAgent: true,
  allowedScopes: [
    "tools:read",
    "tools:twin",
    "tools:vulnerability",
    "tools:blast",
    "tools:attack",
    "tools:evidence",
    "incident:propose",
    "remediation:suggest",
    "twin:query",
    "blast_radius:query",
  ],
  maxRiskTier: "Tier 2",
  cannotApprove: true,
  isActive: true,
  createdAt: new Date().toISOString(),
};
IN_MEMORY_AGENTS.set(DEFAULT_AI_AGENT.id, DEFAULT_AI_AGENT);

export class AgentIdentityService {
  /**
   * Registers or updates an AI agent identity with its specific permission scopes.
   */
  public static async registerAgent(params: {
    id: string;
    tenantId: string;
    name: string;
    allowedScopes: string[];
    maxRiskTier?: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  }): Promise<AIAgentIdentity> {
    const identity: AIAgentIdentity = {
      id: params.id,
      tenantId: params.tenantId,
      name: params.name,
      role: "ai_agent",
      isAiAgent: true,
      allowedScopes: params.allowedScopes,
      maxRiskTier: params.maxRiskTier ?? "Tier 2",
      cannotApprove: true, // Non-negotiable: Rule 5
      isActive: true,
      createdAt: new Date().toISOString(),
    };

    IN_MEMORY_AGENTS.set(params.id, identity);

    try {
      await query(
        `INSERT INTO ai_agent_identities (
          id, tenant_id, name, role, is_ai_agent, allowed_scopes, max_risk_tier, cannot_approve, is_active, created_at
        ) VALUES ($1, $2, $3, 'ai_agent', true, $4, $5, true, true, NOW())
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          allowed_scopes = EXCLUDED.allowed_scopes,
          max_risk_tier = EXCLUDED.max_risk_tier,
          is_active = EXCLUDED.is_active`,
        [params.id, params.tenantId, params.name, params.allowedScopes, identity.maxRiskTier]
      );
    } catch {
      // In-memory fallback
    }

    return identity;
  }

  /**
   * Retrieves an agent identity by ID and verifies tenant binding.
   */
  public static async getAgent(agentId: string, tenantId?: string): Promise<AIAgentIdentity | null> {
    try {
      const sql = tenantId
        ? `SELECT id, tenant_id as "tenantId", name, role, is_ai_agent as "isAiAgent", allowed_scopes as "allowedScopes", max_risk_tier as "maxRiskTier", cannot_approve as "cannotApprove", is_active as "isActive", created_at as "createdAt" FROM ai_agent_identities WHERE id = $1 AND tenant_id = $2 LIMIT 1`
        : `SELECT id, tenant_id as "tenantId", name, role, is_ai_agent as "isAiAgent", allowed_scopes as "allowedScopes", max_risk_tier as "maxRiskTier", cannot_approve as "cannotApprove", is_active as "isActive", created_at as "createdAt" FROM ai_agent_identities WHERE id = $1 LIMIT 1`;
      const params = tenantId ? [agentId, tenantId] : [agentId];
      const res = await query<AIAgentIdentity>(sql, params);
      if (res.rows.length > 0) {
        return res.rows[0];
      }
    } catch {
      // Fallback
    }

    const cached = IN_MEMORY_AGENTS.get(agentId);
    if (cached) {
      if (!tenantId || cached.tenantId === tenantId || cached.tenantId === "*" || cached.tenantId === "system") {
        return cached;
      }
    }

    return null;
  }

  /**
   * Verifies that the agent has the required scope.
   */
  public static assertAgentScope(agent: AIAgentIdentity, requiredScope: string): void {
    if (!agent.isActive) {
      throw new Error(`AI Agent '${agent.id}' is disabled or deactivated.`);
    }

    const hasScope =
      agent.allowedScopes.includes(requiredScope) ||
      agent.allowedScopes.includes("*") ||
      agent.allowedScopes.includes("tools:*") ||
      (requiredScope.startsWith("tools:") && agent.allowedScopes.includes("tools:read"));

    if (!hasScope) {
      throw new Error(
        `AI Agent Permission Denied: Agent '${agent.id}' lacks required scope '${requiredScope}'. Allowed: [${agent.allowedScopes.join(", ")}]`
      );
    }
  }

  /**
   * NON-NEGOTIABLE RULE 5 INVARIANT:
   * "Never allow an agent to approve its own action. Separate proposer from approver."
   * Enforces that:
   * 1. Proposer cannot approve (proposerId !== approverId).
   * 2. AI agents can never approve anything (cannotApprove === true).
   */
  public static assertSeparationOfDuties(proposerId: string, approverId: string, approverIsAi = false): void {
    if (approverIsAi) {
      throw new Error(
        `Rule 5 Violation: AI agent '${approverId}' cannot perform human approval. AI execution of high-impact approvals is strictly forbidden.`
      );
    }

    if (!proposerId || !approverId) {
      throw new Error("Invalid approval context: proposerId and approverId are mandatory.");
    }

    if (proposerId.toLowerCase().trim() === approverId.toLowerCase().trim()) {
      throw new Error(
        `Rule 5 Violation: Separation of duties failure. Proposer '${proposerId}' cannot approve their own proposed action.`
      );
    }
  }
}
