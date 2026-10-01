# Phase H: Execution Broker & Agent Hardening Changelog

**Date:** 2026-10-01  
**Status:** Completed & Verified  
**Branch:** `feature/phase-h-execution-broker`  

---

## 1. Overview & Architectural Goals

Phase H implements the hardened endpoint execution pipeline, enforcing strict cryptographic separation between control plane decision-making and endpoint command execution:
- **Rule 3 — Execution Broker as Single Dispatch Point**: Commands may only be dispatched to endpoint agents via the `ExecutionBroker`. Direct AI-to-endpoint or ad-hoc dispatch paths are structurally forbidden.
- **Rule 8 — Strict Lifecycle State Machine**: Full lifecycle tracking: `REQUESTED` → `APPROVED` → `SIGNED` → `QUEUED` → `DELIVERED` → `EXECUTING` → `EXECUTED` → `VERIFIED` → `ROLLED_BACK`.
- **Short-Lived Ephemeral Credentials**: `generateDispatchToken` issues single-use tokens with a 5-minute TTL, SHA-256 token hashes, and anti-replay nonces stored in `execution_dispatch_tokens`.
- **Rule 2 Invariant (Pre-Execution Snapshot Guard)**: Any Tier 2 or Tier 3 high-impact command dispatched without a verified `snapshotId` fails closed immediately with `Rule 2 Invariant Violation`.
- **Signed Agent Execution Results**: Endpoint agents sign their stdout, stderr, exit codes, and host state digests using enrolled RSA-2048 private keys. The control plane validates these signatures against registered agent keys before transitioning commands to `EXECUTED`.
- **mTLS Device Verification & Revocation Guard**: `MTLSGuard` validates mutual TLS client certificates, enforces strict tenant isolation against spoofing, and checks for certificate revocation or emergency kill switches.
- **Agent Self-Update with Canary Rollback**: `AgentUpdater` publishes canonical update manifests signed with the control plane RSA private key (`signControlPlaneData`). If an update fails health checks or times out on boot, an automated rollback is triggered and recorded on the hash-chain ledger.
- **Cross-Platform Support**: Real Linux (`iptables`) and Windows (`netsh`) command parsing and execution contracts.

---

## 2. Key Modules & Services Created

### A. Execution Broker (`src/lib/fleet/executionBroker.ts`)
- Manages command lifecycle and state transitions.
- Issues 5-minute ephemeral dispatch tokens (`execution_dispatch_tokens`).
- Enforces Rule 2 (fail closed on missing snapshot for Tier 2/Tier 3) and Rule 4 (valid dual human approval token).
- Signs command payloads with RSA-SHA256 control plane key.
- Integrates with tamper-evident Merkle hash chain audit ledger.

### B. Agent Result Verifier (`src/lib/fleet/agentResultVerifier.ts`)
- Formats deterministic canonical result payloads (`commandId|agentId|exitCode|hostStateDigest|executionTimestamp`).
- Computes SHA-256 host state digests of post-execution network, firewall, and process state.
- Cryptographically verifies agent result signatures using enrolled agent public keys.

### C. mTLS Device Guard (`src/lib/fleet/mtlsGuard.ts`)
- Enforces certificate validity, active agent enrollment, and tenant boundaries.
- Rejects revoked client certificates and checks for active emergency kill switches.
- Supports in-memory test agent registries and persistent PostgreSQL verification.

### D. Agent Updater & Canary Engine (`src/lib/fleet/agentUpdater.ts`)
- Releases signed multi-platform manifests (`agent_update_manifests`).
- Evaluates post-update canary health.
- Triggers automated rollback upon boot crash or heartbeat timeout, logging rollback audit events (`agent_update_events`).

### E. Control Plane Cryptographic Helpers (`src/lib/fleet/commandSigning.ts`)
- `signControlPlaneData`: Cryptographically signs arbitrary string data using RSA-SHA256.
- `verifyControlPlaneData`: Verifies control plane signatures with the public key.

### F. REST API Endpoints
- `POST /api/v1/agent/results`: Ingests and cryptographically verifies signed execution results from endpoints.
- `GET /api/v1/agent/update`: Retrieves active update manifests for target platforms.
- `POST /api/v1/agent/update`: Reports post-update canary status and triggers rollback if unhealthy.

### G. Database Migration (`db/migrations/phase_h_execution_broker.sql`)
- `execution_dispatch_tokens`: Ephemeral 5-minute single-use dispatch tokens with anti-replay nonces.
- `agent_update_manifests`: Signed multi-platform agent update release manifests.
- `agent_update_events`: Canary evaluation audit log and automated rollback triggers.

---

## 3. Test Verification & Results

- **Suite:** `tests/phase-h-execution-broker.test.ts`
  - Subtest 1: Rule 2 Invariant: High-impact dispatch without pre-execution snapshot is BLOCKED (PASS)
  - Subtest 2: Ephemeral Dispatch Tokens: Enforces short-lived credentials and anti-replay nonces (PASS)
  - Subtest 3: Lifecycle State Machine: Transitions through SIGNED -> QUEUED -> DELIVERED (PASS)
  - Subtest 4: Signed Agent Execution Results: Verifies cryptographic agent signature & state digest (PASS)
  - Subtest 5: mTLS Device Verification Guard: Rejects revoked certificates & kill switches (PASS)
  - Subtest 6: Agent Self-Update & Canary Rollback: Verifies manifests & triggers rollback on failure (PASS)
  - **Result: 7/7 tests passing (100% green).**

- **Full Repository Suite (`npm test`):**
  - **286 passing tests** across 39 test suites with **0 failures**.
