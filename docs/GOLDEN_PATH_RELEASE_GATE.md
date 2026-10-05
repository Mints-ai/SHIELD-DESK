# Golden-path release gate

The `Simulated Golden Path & Rollback Release Gate` CI job runs the repository's golden-path, closed-loop orchestration, and rollback failure-injection suites. This is a software regression gate over mock/in-memory agents, telemetry, AI output, and evidence; it is not an end-to-end customer-host certification.

Current test coverage exercises MFA setup, X.509 certificate issuance, telemetry ingestion, a Wazuh connector event, digital twin, attack-path and blast-radius calculations, mock AI investigation, decision evaluation, closed-loop orchestration, evidence-package generation, and separate rollback failure branches.

The test does not yet prove a live signup flow, TOTP challenge completion, real mTLS agent enrollment, customer incident persistence, actual endpoint execution, or host restoration. Those checks remain open in `docs/PRODUCTION_LAUNCH_CHECKLIST.md` and require the endpoint matrix and a pilot. Repository administrators must set this job as a required branch-protection status check.
