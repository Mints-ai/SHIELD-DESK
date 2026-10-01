import { z } from "zod";

export type LLMProviderType = "ollama" | "gemini" | "openai" | "claude" | "mock";

export const EvidenceCitationSchema = z.object({
  evidenceId: z.string().min(1),
  source: z.string().min(1), // e.g. "finding", "twin_node", "evidence_engine", "telemetry"
  claim: z.string().min(3),
  verified: z.boolean().default(true),
  confidence: z.number().min(0.0).max(1.0).default(1.0),
});

export type EvidenceCitation = z.infer<typeof EvidenceCitationSchema>;

export const RemediationActionSchema = z.object({
  action: z.string().min(2),
  targetAsset: z.string().min(1),
  reason: z.string().min(5),
  risk: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  parameters: z.record(z.string(), z.unknown()).optional(),
  evidenceIds: z.array(z.string()).default([]),
});

export const StructuredInvestigationSchema = z.object({
  analysis: z.string().min(10),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  confidence: z.number().min(0.0).max(1.0),
  evidence: z.array(z.string()).min(1),
  evidenceCitations: z.array(EvidenceCitationSchema).default([]),
  recommended_actions: z.array(RemediationActionSchema),
  attackTechnique: z.string().optional(),
  modelAttribution: z.object({
    provider: z.string(),
    model: z.string(),
    promptVersion: z.string(),
  }).optional(),
});

export const RemediationProposalSchema = z.object({
  proposalId: z.string(),
  tenantId: z.string(),
  incidentId: z.string().optional(),
  title: z.string().min(5),
  summary: z.string().min(10),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  suggestedTier: z.enum(["Tier 0", "Tier 1", "Tier 2", "Tier 3"]),
  proposerAgentId: z.string(),
  actions: z.array(RemediationActionSchema).min(1),
  evidenceCitations: z.array(EvidenceCitationSchema).min(1),
  aiConfidence: z.number().min(0.0).max(1.0),
  modelAttribution: z.object({
    provider: z.string(),
    model: z.string(),
    promptVersion: z.string(),
  }),
  isExecutable: z.literal(false).default(false), // AI output is structured proposal only; direct execution forbidden
  requiresHumanApproval: z.literal(true).default(true),
  createdAt: z.string(),
});

export type StructuredInvestigation = z.infer<typeof StructuredInvestigationSchema>;
export type RemediationAction = z.infer<typeof RemediationActionSchema>;
export type RemediationProposal = z.infer<typeof RemediationProposalSchema>;

export interface LLMRequestOptions {
  provider?: LLMProviderType;
  model?: string;
  temperature?: number;
  promptVersion?: string;
  tenantId: string;
  actorId: string;
  agentIdentityId?: string;
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
  citationsCount?: number;
}

export interface AIAgentIdentity {
  id: string;
  tenantId: string;
  name: string;
  role: string;
  isAiAgent: boolean;
  allowedScopes: string[];
  maxRiskTier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  cannotApprove: boolean; // Hardcoded true
  isActive: boolean;
  createdAt: string;
}

export interface AIPromptVersion {
  id: string;
  promptName: string;
  version: string;
  provider: LLMProviderType;
  modelName: string;
  systemPrompt: string;
  userTemplate: string;
  temperature: number;
  schemaDefinition: Record<string, unknown>;
  sha256Hash: string;
  isActive: boolean;
  createdAt: string;
}

export interface AIEvalBenchmarkCase {
  id: string;
  category:
    | "incident_triage"
    | "root_cause_analysis"
    | "remediation_proposal"
    | "prompt_injection_defense"
    | "hallucination_trap"
    | "tool_authorization_abuse";
  title: string;
  description: string;
  inputTelemetry: Record<string, unknown> | Array<unknown>;
  expectedSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  expectedActions: Array<{ action: string; targetAsset: string }>;
  expectedEvidenceKeys: string[];
  injectionPayload?: string;
  isActive: boolean;
}

export interface AIEvalRunResult {
  runId: string;
  tenantId: string;
  runBy: string;
  modelName: string;
  provider: string;
  promptVersion: string;
  totalCases: number;
  passedCases: number;
  hallucinationRate: number; // 0.0 - 1.0
  remediationAccuracy: number; // 0.0 - 1.0
  toolCallErrorRate: number; // 0.0 - 1.0
  avgLatencyMs: number;
  details: {
    caseResults: Array<{
      caseId: string;
      category: string;
      passed: boolean;
      hallucinated: boolean;
      toolCallSuccess: boolean;
      notes: string;
    }>;
  };
  createdAt: string;
}
