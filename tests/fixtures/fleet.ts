import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";

// Explicit test data: imported only by suites that require an enrolled fleet.
// Runtime registries remain empty until real enrollment occurs.
const now = new Date().toISOString();
const hosts = [
 ["ea111111-1111-1111-1111-111111111111", "FIN-WS-042", "acme-tenant", "10.20.0.11"],
 ["ea222222-2222-2222-2222-222222222222", "FIN-DB-01", "acme-tenant", "10.20.0.12"],
 ["ea333333-3333-3333-3333-333333333333", "PROD-API-01", "acme-tenant", "10.20.0.13"],
 ["ea444444-4444-4444-4444-444444444444", "SOC-WORKER-01", "acme-tenant", "10.20.0.14"],
 ["ea555555-5555-5555-5555-555555555555", "GLOBEX-WS-01", "globex-tenant", "10.30.0.11"],
];
for (const [id, hostname, tenant_id, ip_address] of hosts) {
 MOCK_ENDPOINT_AGENTS.push({id,hostname,tenant_id,ip_address,os_type:"linux",agent_version:"test-fixture",status:"connected",cpu_usage:10,memory_usage:20,eps:30,kill_switch_active:false,safety_snapshot_id:null,last_heartbeat:now,created_at:now});
}
