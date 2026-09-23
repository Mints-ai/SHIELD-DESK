# ShieldDesk Universal Endpoint Agent (Layer 2 — The Hands)

> **The host-level execution and telemetry engine of the ShieldDesk Autonomous SOC platform. It runs on protected endpoints, captures system and network telemetry, enforces safety snapshots, and executes authorized Tier 1–3 containment actions.**

---

## Architecture: Dual-Language Design (Go + Rust)

To guarantee both high-throughput telemetry handling and zero-compromise safety on destructive operations, the endpoint agent is divided into two distinct components:

```
+---------------------------------------------------------------------------------+
|                               PROTECTED ENDPOINT HOST                           |
|                                                                                 |
|   +---------------------------------------+   +-------------------------------+ |
|   |         MAIN AGENT (Go)               |   |     PRIVILEGED DAEMON (Rust)  | |
|   | • Telemetry collection & filtering    |   | • Tier 3 Break-Glass Sentinel | |
|   | • 10,000-event RingBuffer (Offline)   |   | • Two-Person Rule Enforcement | |
|   | • Tier 1 (Autonomous) Action Engine   |   | • Named SuperAdmin Sign-Off   | |
|   | • Tier 2 (Human-Gated) Action Engine  |   | • Local SHA-256 Hash Chained  | |
|   | • Pre-Flight Safety Snapshots         |   |   Immutable Audit Ledger      | |
|   +-------------------+-------------------+   +---------------+---------------+ |
|                       |                                       |                 |
+-----------------------|---------------------------------------|-----------------+
                        |                                       |
                        v                                       v
         POST /api/fleet (Heartbeat & Telemetry)    POST /api/fleet/kill-switch
                        |                                       |
                        +-------------------+-------------------+
                                            |
                                            v
                        +---------------------------------------+
                        |      SHIELDDESK CONTROL PLANE         |
                        |     (http://localhost:3000)           |
                        | • Fleet Management: /dashboard/fleet  |
                        | • 24h Signed Execution Tokens         |
                        | • Emergency Fleet Kill Switch         |
                        +---------------------------------------+
```

### 1. Main Agent (Go)
- **High Concurrency & Low Memory Footprint**: Runs silently in the background, monitoring system processes, active sockets, and network events.
- **Offline Telemetry Ring Buffer (`pkg/telemetry/buffer.go`)**: 10,000-slot memory ring-buffer preserves events during network disconnects and auto-flushes upon reconnection.
- **Pre-Flight Safety Snapshots (`pkg/handlers/actions.go`)**: Before executing any host modification (firewall rule addition, process kill, interface disable), a local state snapshot is captured to allow zero-downtime automated rollback.
- **Action Execution**:
  - **Tier 1 (Autonomous)**: Immediate low-risk actions (e.g., invalidate user session tokens).
  - **Tier 2 (Human-Gated)**: Medium-risk actions requiring verified human approval tokens (e.g., network interface quarantine on `FIN-WS-042`).

### 2. Privileged Daemon (Rust)
- **Zero-Overhead Memory Safety**: Built in Rust for maximum reliability under emergency circumstances.
- **Tier 3 Emergency Break-Glass Sentinel**: Manages critical and destructive operations (e.g., core system shutdowns, global firewall flushes).
- **Two-Person Rule**: Strictly enforces that Tier 3 commands must present two distinct, non-expired cryptographic signatures from the Named SuperAdmin roster.
- **Local Append-Only Hash Chain (`pkg/audit/hashchain.go`)**: Every local action is permanently hashed using `SHA-256(prev_hash + entry)` to prevent log tampering even if root privileges are compromised.

---

## Package Structure

```
agent/
├── cmd/
│   └── main.go                 # Go agent entrypoint, flags & lifecycle management
├── pkg/
│   ├── audit/
│   │   └── hashchain.go        # Cryptographic hash-chained audit ledger
│   ├── handlers/
│   │   └── actions.go          # Tier 1/2 action execution & safety snapshot engine
│   └── telemetry/
│       └── buffer.go           # 10,000-event ring-buffer for network disconnect resilience
├── rust_daemon/
│   ├── Cargo.toml              # Rust crate manifest
│   └── src/
│       └── main.rs             # Tier 3 break-glass sentinel & two-person rule enforcement
├── go.mod                      # Go module definition
└── README.md
```

---

## Compilation & Run Instructions

### 1. Run the Go Agent
```bash
cd agent
go run cmd/main.go \
  -control-url http://localhost:3000 \
  -agent-id ea111111-1111-1111-1111-111111111111 \
  -tenant-id acme-tenant \
  -hostname FIN-WS-042
```

### 2. Build the Rust Tier 3 Daemon
```bash
cd agent/rust_daemon
cargo build --release
./target/release/shielddesk-tier3-daemon
```

---

## Security Verification & Fleet Controls

- **Live Fleet Management**: View registered endpoints, EPS telemetry, and host health in the ShieldDesk dashboard at `http://localhost:3000/dashboard/fleet`.
- **Emergency Admin Kill Switch**: System administrators can instantly disengage and freeze all endpoint agent actions via `POST /api/fleet/kill-switch` directly from the dashboard header.
- **Automated Test Validation**: Layer 2 agent behaviors (tenant isolation, Tier 1 auto-execution, Tier 2 governance gating, anti-enumeration, and kill switch operations) are verified in `tests/fleet.test.ts`.
