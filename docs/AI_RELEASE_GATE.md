# AI release gate

The `AI Safety & Evaluation Release Gate` CI job runs the AI prompt-defense, structured-output, tool authorization, fallback/failure, evidence-citation, and benchmark suites on pull requests and pushes to `main`. The permanent evaluation checks versioned prompt metadata and records provider/model/prompt version, case pass count, hallucination rate, remediation accuracy, tool error rate, and mean local latency.

## Current acceptance criteria

- All active deterministic benchmark cases pass.
- Hallucination rate is zero and remediation accuracy is 100% for the fixed benchmark.
- Unauthorized tool error rate is zero under expected rejection behavior.
- Mock-provider mean case latency is under 5 seconds.
- Prompt integrity validation and the existing prompt-injection, schema, tool-misuse, and provider-failure tests pass.

## Limits and release-owner actions

- This gate uses deterministic test/mock inputs; it does not establish real-provider behavior.
- Provider cost is not currently measured because token usage/cost is not carried through `AIEvaluationLab`. Cost tracking remains **IMPLEMENTED: not yet** and must be added before setting a monetary CI budget.
- Mean local mock latency is a regression guard, not a production latency SLO. Track p95/p99 against a real provider before release.
- Repository administrators must make the `AI Safety & Evaluation Release Gate` status check required in branch protection. Workflow code cannot configure that repository setting.
- Maintain reviewed, versioned datasets and prompt/model records; add a release note when baselines change. Never tune a benchmark to conceal a regression.
