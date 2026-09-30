# Phase 8, 10 & 11 Changelog: Real Endpoint Agent, Capabilities Registry & Anti-Replay Defense

## Overview
Enforces the Master Prompt Section 20, 24, and 25 requirements:
1. **Capabilities Specification & Registry**: Strict definition of 10 core endpoint capabilities with risk tiers, approval requirements, rollback support, and OS compatibility (`network.isolate`, `network.restore`, `process.terminate`, `process.inspect`, `snapshot.create`, `snapshot.restore`, `patch.apply`, `service.restart`, `file.quarantine`, `firewall.block`).
2. **OS Compatibility Enforcement**: Automatic rejection in `executeAgentCommand` if a requested action is unsupported on target OS (e.g., rejecting Linux-only or Windows-only capabilities on Darwin/macOS).
3. **Cryptographic Anti-Replay Defense**: Added thread-safe nonce tracking and anti-replay rejection in Go endpoint agent (`agent/cmd/main.go`), ensuring no signed command nonce can ever be executed twice.

## Key Changes
- `src/lib/fleet/capabilities.ts`: Defined `AgentCapability`, `CAPABILITY_REGISTRY`, `getCapability`, `validateCapabilitySupport`, and `listCapabilities`.
- `src/lib/fleet/fleet.ts`: Integrated capability validation into `executeAgentCommand` prior to signing and enqueuing.
- `agent/cmd/main.go`: Added thread-safe nonce tracking (`isNonceReplayed`) and rejection in `pollCommands()` after signature verification.
- `tests/agent-capabilities-and-replay-defense.test.ts`: Added unit tests verifying capability definitions, legacy alias resolution, OS compatibility checks, OS-based rejection in command execution, and anti-replay verification.

## Verification
- All 20 test suites and 151 unit/integration tests passing (0 failures).
- Complete cryptographic signature + nonce binding verified.
