# Phase G: AI Layer, Governance & Evaluation Lab Changelog

**Date:** 2026-10-01  
**Status:** Completed & Verified  
**Branch:** `feature/phase-g-ai-layer`  

---

## 1. Overview & Architectural Goals

Phase G delivers the enterprise AI governance layer, model-agnostic LLM gateway, and quantitative AI evaluation lab:
- **Provider-Independent LLM Gateway**: Local-first Ollama as default (`qwen3:4b`), alongside Gemini, OpenAI, Claude, and Mock adapters.
- **Rule 1 & Rule 2 Enforcement**: AI generates strictly structured proposals (`StructuredInvestigation`, `RemediationProposal`). Direct command execution from AI is structurally forbidden (`isExecutable: false`, `requiresHumanApproval: true`).
- **Rule 5 Invariant**: "Never allow an agent to approve its own action. Separate proposer from approver." Enforced in `AgentIdentityService.assertSeparationOfDuties`: AI agents can never approve, and human proposers cannot self-approve.
- **Prompt & Model Versioning**: Dedicated PostgreSQL table `ai_prompt_versions` tracking prompt templates, versions, model names, system prompts, schemas, and SHA-256 integrity hashes with runtime tampering detection.
- **Evidence Citations**: Every claim and action in an AI proposal must carry verifiable citations linking to genuine security evidence (from Phase D Evidence Engine, Phase A findings, or Phase B Twin Nodes). Unsubstantiated or fabricated claims directly degrade confidence and trigger hallucination alerts.
- **AI Evaluation Lab**: Permanent benchmark dataset in PostgreSQL (`ai_eval_benchmark_dataset`) covering triage, root cause analysis, prompt injection defense, hallucination traps, and tool authorization abuse.
- **Quantitative Quality Metrics**: Calculates and logs `hallucination_rate`, `remediation_accuracy`, `tool_call_error_rate`, and `avg_latency_ms` to `ai_eval_runs`.
- **Safe Tool Router**: Enforces strict allow-lists, per-agent permission scopes, tenant isolation, and blocks arbitrary or state-mutating commands.

---

## 2. Key Modules & Services Created

### A. AI Core Types & Schemas (`src/lib/ai/types.ts`)
- `EvidenceCitationSchema`: Validated citation with `evidenceId`, `source`, `claim`, `verified`, and `confidence`.
- `RemediationProposalSchema`: Structured proposal with non-executable guarantee (`isExecutable: false`), mandatory human sign-off (`requiresHumanApproval: true`), and explicit `evidenceCitations`.
- `AIAgentIdentity`: Agent identity metadata with scoped permissions and `cannotApprove: true` constraint.
- `AIPromptVersion`: Versioned prompt record with model attribution and SHA-256 integrity hash.
- `AIEvalBenchmarkCase` & `AIEvalRunResult`: Evaluation dataset and execution results schema.

### B. Prompt Registry (`src/lib/ai/promptRegistry.ts`)
- Manages versioned system/user prompts and schema definitions.
- Computes canonical SHA-256 hash across prompt definitions.
- `verifyIntegrity`: Verifies that loaded prompt definitions match their registered SHA-256 hash, detecting prompt tampering.

### C. Agent Identity & Scope Service (`src/lib/ai/agentIdentity.ts`)
- Scopes AI agents to permitted operations (`tools:read`, `incident:propose`, `remediation:suggest`, `twin:query`, etc.).
- Enforces Non-Negotiable Rule 5:
  - Blocks proposer from approving own action (`proposerId === approverId`).
  - Hardcodes `cannotApprove: true` for all AI agents.

### D. Evidence Citation Validator (`src/lib/ai/evidenceCitations.ts`)
- Validates citations against Phase D `EvidenceEngine`, Phase A vulnerability findings, and Phase B digital twin nodes.
- Computes `hallucinationScore` based on the ratio of invalid or fabricated citations.
- Penalizes AI confidence when citations fail verification.

### E. Safe Tool Router (`src/lib/ai/toolRouter.ts`)
- Only allows registered query tools (`twin_dependency_query`, `vulnerability_lookup`, `blast_radius_estimate`, `attack_path_inspect`, `evidence_verify`).
- Checks caller agent identity and required permission scopes.
- Blocks unauthorized or destructive tool execution deterministically.
- Tracks operational tool-call metrics and error rates.

### F. AI Evaluation Lab (`src/lib/ai/evaluationLab.ts`)
- Maintains permanent benchmark dataset `PERMANENT_BENCHMARK_CASES` covering 5 key categories:
  1. `incident_triage` (Cobalt Strike lateral movement)
  2. `root_cause_analysis` (Log4j RCE CVE-2021-44228)
  3. `prompt_injection_defense` (Adversarial override attempt)
  4. `hallucination_trap` (Ambiguous anomaly with zero exploit evidence)
  5. `tool_authorization_abuse` (Attempt to call destructive tool)
- Computes deterministic quality metrics: `hallucination_rate`, `remediation_accuracy`, `tool_call_error_rate`, `avg_latency_ms`.
- Records historical runs in `ai_eval_runs` table.

### G. Enhanced LLM Gateway (`src/lib/ai/gateway.ts`)
- Supports local-first Ollama via OpenAI-compatible endpoint as default.
- Pluggable support for Gemini, OpenAI, Claude, and Mock (dev-only gated).
- Proposes structured investigations and remediation plans with verified evidence citations.

### H. API Routes Created
- `POST /api/v1/ai/proposals`: Synthesizes structured investigation or remediation proposal with citation validation.
- `GET /api/v1/ai/evaluation`: Retrieves past AI Evaluation Lab runs and benchmark cases.
- `POST /api/v1/ai/evaluation`: Triggers automated AI Evaluation Lab benchmark run.

### I. Database Migration (`db/migrations/phase_g_ai_evaluation.sql`)
- `ai_prompt_versions`: Prompt and model versioning ledger with SHA-256 hashes.
- `ai_agent_identities`: Agent identities with allowed scopes and `cannot_approve` constraints.
- `ai_eval_benchmark_dataset`: Permanent evaluation benchmark test cases.
- `ai_eval_runs`: Evaluation run metrics and performance records.

---

## 3. Test Coverage & Verification

- **Dedicated Suite:** `tests/phase-g-ai-layer.test.ts` (9 tests passing).
- **Total Test Suite:** **279 / 279 tests passing (100% green)** across 38 suites (`npm test`).
- Zero regressions in existing baseline, auth, governance, digital twin, or verification engines.
