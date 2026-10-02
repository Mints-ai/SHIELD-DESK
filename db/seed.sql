-- Production baseline seeds. Dev personas are separated in db/seed.dev.sql
INSERT INTO users (id, tenant_id, role, email) VALUES
  ('system-air', 'acme-tenant', 'system_admin', 'system-air@internal.shielddesk')
ON CONFLICT (id) DO NOTHING;


INSERT INTO assets (id, tenant_id, hostname, asset_type) VALUES
  ('a1111111-1111-1111-1111-111111111111', 'acme-tenant', 'FIN-WS-042', 'workstation'),
  ('a2222222-2222-2222-2222-222222222222', 'acme-tenant', 'FIN-DB-01',  'database-server')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Seed Endpoint Agents (Layer 2 Pilot Test Hosts)
-- Matches Phase 2b pilot requirements: Windows + Linux test hosts
-- ---------------------------------------------------------------------------
INSERT INTO endpoint_agents (
  id, tenant_id, hostname, ip_address, os_type, agent_version, status, cpu_usage, memory_usage, eps, kill_switch_active, safety_snapshot_id
) VALUES
  ('ea111111-1111-1111-1111-111111111111', 'acme-tenant', 'FIN-WS-042', '10.0.4.42', 'windows', '0.4.2', 'connected', 42.5, 68.2, 145, false, 'snap-finws042-baseline'),
  ('ea222222-2222-2222-2222-222222222222', 'acme-tenant', 'FIN-DB-01',  '10.0.4.10', 'linux',   '0.4.2', 'connected', 18.2, 84.1, 412, false, 'snap-findb01-baseline'),
  ('ea333333-3333-3333-3333-333333333333', 'acme-tenant', 'ENG-LAPTOP-09', '10.0.12.9', 'linux',   '0.4.2', 'connected', 12.1, 45.0, 32, false, 'snap-eng09-baseline'),
  ('ea444444-4444-4444-4444-444444444444', 'acme-tenant', 'PROD-API-01', '10.0.2.100', 'linux',   '0.4.2', 'connected', 64.8, 71.3, 890, false, 'snap-prodapi-baseline'),
  ('ea555555-5555-5555-5555-555555555555', 'globex-tenant', 'GLX-SEC-01', '192.168.1.15', 'linux', '0.4.2', 'connected', 15.0, 38.0, 80, false, 'snap-glx01-baseline')
ON CONFLICT (id) DO NOTHING;

-- Seed Command Log
INSERT INTO agent_command_logs (
  id, agent_id, tenant_id, command, tier, token_id, status, output, executed_by
) VALUES
  ('f1111111-1111-1111-1111-111111111111', 'ea111111-1111-1111-1111-111111111111', 'acme-tenant', 'take_safety_snapshot', 'Tier 1', NULL, 'succeeded', 'Snapshot snap-finws042-baseline captured successfully (file integrity + routing table).', 'system-air'),
  ('f2222222-2222-2222-2222-222222222222', 'ea111111-1111-1111-1111-111111111111', 'acme-tenant', 'block_ip 198.51.100.4', 'Tier 1', NULL, 'succeeded', 'Host firewall rule added: DROP IN/OUT 198.51.100.4. Verified reversible.', 'system-air')
ON CONFLICT (id) DO NOTHING;

-- Seed Hash-Chained Audit Trail (Genesis block and initial chained event)
INSERT INTO hash_chain_audit (
  id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash
) VALUES
  ('00000000-0000-0000-0000-000000000000', 'acme-tenant', 'GENESIS', 'system-init', '{"msg":"ShieldDesk Hash Chain Genesis"}'::jsonb, '0000000000000000000000000000000000000000000000000000000000000000', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
  ('00000001-1111-1111-1111-111111111111', 'acme-tenant', 'TOKEN_REQUEST', 'system-air', '{"action":"isolate_host","host":"FIN-WS-042","tier":"Tier 2"}'::jsonb, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'a1f8c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b899')
ON CONFLICT (id) DO NOTHING;


