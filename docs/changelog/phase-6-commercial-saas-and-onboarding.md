# Phase 6 Changelog: Multi-Tenant Enterprise Security & Commercial SaaS

## Overview
Enforces the Master Prompt Section 40 & 41 requirements:
1. **Cryptographic Commercial License Verification (`src/lib/billing/licenses.ts`)**:
   - Built cryptographic HMAC-SHA256 signed license tokens (`issueCommercialLicense`).
   - Implemented validation for expiration dates, entitlement quotas, and anti-tamper signature checking (`verifyCommercialLicense`).
2. **Tier Quota & Over-Quota Governance (`src/lib/billing/plans.ts`)**:
   - Implemented `evaluateQuotaStatus()` adhering to Section 40:
     - Soft warning at 90% endpoint capacity.
     - Grace period at 100% capacity.
     - Hard block on new agent enrollments at 110%+ capacity.
     - **Critical Invariant**: Telemetry ingestion and active agents are never killed or dropped due to quota overflow.
3. **Usage Metering (`src/lib/billing/metering.ts`)**:
   - Tracked usage across 4 dimensions: active endpoints count, telemetry bytes ingested, remediation actions executed, and AI tokens consumed.
   - Monthly usage aggregation reporting (`getTenantUsageReport()`).
4. **Customer Onboarding Golden Path (`src/lib/onboarding/goldenPath.ts`)**:
   - 15-minute time-to-value milestone progression: `SIGNUP` $\rightarrow$ `ORGANIZATION_CREATED` $\rightarrow$ `ENROLLMENT_TOKEN_ISSUED` $\rightarrow$ `INSTALLATION_COMMAND_GENERATED` $\rightarrow$ `FIRST_AGENT_CONNECTED` $\rightarrow$ `CANARY_DETECTION_TRIGGERED` $\rightarrow$ `INCIDENT_SURFACED` $\rightarrow$ `FIRST_REMEDIATION_VERIFIED`.
   - Multi-platform one-line installation command generation (Linux `curl` and Windows PowerShell).
   - Benign canary incident generator (`generateCanaryDetection`) for safe first-run remediation testing.

## Key Changes
- `src/lib/billing/licenses.ts`: Cryptographic commercial licensing engine.
- `src/lib/billing/plans.ts`: Added `evaluateQuotaStatus()` and `QuotaEvaluation` type.
- `src/lib/billing/metering.ts`: New usage metering module.
- `src/lib/onboarding/goldenPath.ts`: Customer onboarding state machine, install script generators, and canary triggers.
- `tests/commercial-saas-and-onboarding.test.ts`: Dedicated unit test suite for licensing, quotas, metering, and golden path milestones.

## Verification
- All 23 test suites and 168 unit/integration tests passing (0 failures).
- TypeScript strict compilation passed cleanly (0 errors).
