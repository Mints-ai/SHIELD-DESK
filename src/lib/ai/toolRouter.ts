import "server-only";
import { AgentIdentityService } from "./agentIdentity";
import { AIAgentIdentity } from "./types";
import { SecurityDigitalTwin } from "@/lib/security-twin/digitalTwin";
import { EvidenceEngine } from "@/lib/decision-engine/evidenceEngine";
import { BlastRadiusEngine } from "@/lib/blast-radius/engine";
import { AttackPathEngine } from "@/lib/attack-path/engine";

export interface ToolCallRequest {
  toolName: string;
  arguments: Record<string, unknown>;
  agentIdentityId: string;
  tenantId: string;
}

export interface ToolCallResult {
  toolName: string;
  success: boolean;
  result?: unknown;
  error?: string;
  errorCode?: "UNAUTHORIZED" | "FORBIDDEN_SCOPE" | "INVALID_ARGUMENTS" | "TOOL_NOT_FOUND" | "EXECUTION_ERROR";
}

export class ToolRouter {
  private static toolCallCount = 0;
  private static toolErrorCount = 0;

  // Registered read/query tools that AI agents are permitted to invoke
  private static readonly ALLOWED_TOOLS = new Set([
    "twin_dependency_query",
    "vulnerability_lookup",
    "blast_radius_estimate",
    "attack_path_inspect",
    "evidence_verify",
  ]);

  /**
   * Dispatches a tool call with strict agent identity, tenant isolation, and RBAC scoping.
   * High-impact mutating execution is strictly forbidden.
   */
  public static async executeTool(
    request: ToolCallRequest,
    agentIdentity?: AIAgentIdentity
  ): Promise<ToolCallResult> {
    this.toolCallCount++;

    // 1. Resolve agent identity
    const agent =
      agentIdentity || (await AgentIdentityService.getAgent(request.agentIdentityId, request.tenantId));

    if (!agent) {
      this.toolErrorCount++;
      return {
        toolName: request.toolName,
        success: false,
        error: `Unknown or unverified AI Agent identity: '${request.agentIdentityId}'`,
        errorCode: "UNAUTHORIZED",
      };
    }

    // 2. Check if tool is allow-listed
    if (!this.ALLOWED_TOOLS.has(request.toolName)) {
      this.toolErrorCount++;
      return {
        toolName: request.toolName,
        success: false,
        error: `Tool '${request.toolName}' is not in the allow-listed AI tool registry. Direct execution of arbitrary or state-mutating actions is forbidden.`,
        errorCode: "TOOL_NOT_FOUND",
      };
    }

    // 3. Check agent permission scopes
    const requiredScope = `tools:${request.toolName.split("_")[0]}`;
    try {
      AgentIdentityService.assertAgentScope(agent, requiredScope);
    } catch (err: unknown) {
      this.toolErrorCount++;
      return {
        toolName: request.toolName,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        errorCode: "FORBIDDEN_SCOPE",
      };
    }

    // 4. Dispatch deterministic tool query
    try {
      const output = await this.dispatch(request.toolName, request.arguments, request.tenantId);
      return {
        toolName: request.toolName,
        success: true,
        result: output,
      };
    } catch (err: unknown) {
      this.toolErrorCount++;
      return {
        toolName: request.toolName,
        success: false,
        error: `Tool execution failed: ${err instanceof Error ? err.message : String(err)}`,
        errorCode: "EXECUTION_ERROR",
      };
    }
  }

  private static async dispatch(toolName: string, args: Record<string, unknown>, tenantId: string): Promise<unknown> {
    switch (toolName) {
      case "twin_dependency_query": {
        const assetId = String(args.assetId || "");
        if (!assetId) throw new Error("Missing mandatory parameter 'assetId'");
        return SecurityDigitalTwin.getDependencies(tenantId, assetId);
      }

      case "vulnerability_lookup": {
        const cveId = String(args.cveId || "");
        if (!cveId) throw new Error("Missing mandatory parameter 'cveId'");
        return {
          cveId,
          cvssV3Score: 8.8,
          epssScore: 0.72,
          isKev: true,
          description: `Simulated intelligence metadata for ${cveId}`,
        };
      }

      case "blast_radius_estimate": {
        const assetId = String(args.assetId || "");
        const actionType = String(args.actionType || "isolate_host");
        if (!assetId) throw new Error("Missing mandatory parameter 'assetId'");
        return BlastRadiusEngine.evaluateBlastRadius(assetId, actionType);
      }

      case "attack_path_inspect": {
        const sourceAsset = String(args.sourceAsset || "");
        const targetAsset = String(args.targetAsset || "");
        return AttackPathEngine.calculateAttackPaths(sourceAsset, targetAsset);
      }

      case "evidence_verify": {
        const evidenceId = String(args.evidenceId || "");
        const record = EvidenceEngine.getEvidence(evidenceId);
        return {
          evidenceId,
          exists: Boolean(record),
          record: record || null,
        };
      }

      default:
        throw new Error(`Unhandled tool dispatcher: ${toolName}`);
    }
  }

  public static getMetrics(): { totalCalls: number; errorCalls: number; errorRate: number } {
    const errorRate = this.toolCallCount === 0 ? 0 : Number((this.toolErrorCount / this.toolCallCount).toFixed(4));
    return {
      totalCalls: this.toolCallCount,
      errorCalls: this.toolErrorCount,
      errorRate,
    };
  }

  public static resetMetrics(): void {
    this.toolCallCount = 0;
    this.toolErrorCount = 0;
  }
}
