import { z } from "zod";

export type LLMProviderType = "gemini" | "openai" | "claude" | "ollama" | "mock";

export const RemediationActionSchema = z.object({
  action: z.string().min(2),
  targetAsset: z.string().min(1),
  reason: z.string().min(5),
  risk: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  parameters: z.record(z.string(), z.unknown()).optional(),
});

export const StructuredInvestigationSchema = z.object({
  analysis: z.string().min(10),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  confidence: z.number().min(0.0).max(1.0),
  evidence: z.array(z.string()).min(1),
  recommended_actions: z.array(RemediationActionSchema),
  attackTechnique: z.string().optional(),
  modelAttribution: z.object({
    provider: z.string(),
    model: z.string(),
    promptVersion: z.string(),
  }).optional(),
});

export type StructuredInvestigation = z.infer<typeof StructuredInvestigationSchema>;
export type RemediationAction = z.infer<typeof RemediationActionSchema>;

export interface LLMRequestOptions {
  provider?: LLMProviderType;
  model?: string;
  temperature?: number;
  promptVersion?: string;
  tenantId: string;
  actorId: string;
}

export interface AIExecutionAuditRecord {
  auditId: string;
  tenantId: string;
  timestamp: string;
  provider: LLMProviderType;
  model: string;
  promptVersion: string;
  inputContextDigest: string;
  toolsAllowed: string[];
  sanitized: boolean;
  outputSeverity: string;
  actionsCount: number;
}
