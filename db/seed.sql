-- Sample data for local development. One tenant, a few incidents/assets,
-- and a couple of dev users at different roles so RBAC is actually
-- exercisable, not just theoretical.

INSERT INTO users (id, tenant_id, role) VALUES
  ('dev-analyst', 'acme-tenant', 'user'),
  ('dev-admin',   'acme-tenant', 'system_admin'),
  ('dev-other',   'globex-tenant', 'user')
ON CONFLICT (id) DO NOTHING;

INSERT INTO assets (id, tenant_id, hostname, asset_type) VALUES
  ('a1111111-1111-1111-1111-111111111111', 'acme-tenant', 'FIN-WS-042', 'workstation'),
  ('a2222222-2222-2222-2222-222222222222', 'acme-tenant', 'FIN-DB-01',  'database-server')
ON CONFLICT (id) DO NOTHING;

INSERT INTO incidents (id, incident_code, tenant_id, severity, status, title, description) VALUES
  ('11111111-1111-1111-1111-111111111111', 'INC-1042', 'acme-tenant', 'critical', 'investigating',
   'Suspicious lateral movement on FIN-WS-042',
   'Detected lateral movement attempt from FIN-WS-042 toward the finance subnet. Two affected assets so far. No confirmed data exfiltration.'),
  ('22222222-2222-2222-2222-222222222222', 'INC-1039', 'acme-tenant', 'high', 'open',
   'Repeated failed admin logins, EU tenant',
   'Multiple failed administrator login attempts detected from an external IP range.'),
  ('33333333-3333-3333-3333-333333333333', 'INC-1031', 'acme-tenant', 'medium', 'resolved',
   'Outbound traffic to a newly-registered domain',
   'Endpoint contacted a domain registered within the last 48 hours; blocked by egress filtering.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO incident_events (incident_id, occurred_at, description)
SELECT '11111111-1111-1111-1111-111111111111', now() - interval '3 hours', 'Initial detection: anomalous SMB traffic from FIN-WS-042.'
WHERE NOT EXISTS (SELECT 1 FROM incident_events WHERE incident_id = '11111111-1111-1111-1111-111111111111' AND description LIKE 'Initial detection%');

INSERT INTO incident_events (incident_id, occurred_at, description)
SELECT '11111111-1111-1111-1111-111111111111', now() - interval '2 hours', 'Confirmed lateral movement attempt toward FIN-DB-01.'
WHERE NOT EXISTS (SELECT 1 FROM incident_events WHERE incident_id = '11111111-1111-1111-1111-111111111111' AND description LIKE 'Confirmed lateral movement%');

INSERT INTO incident_events (incident_id, occurred_at, description)
SELECT '11111111-1111-1111-1111-111111111111', now() - interval '1 hour',  'Analyst assigned; containment options under review.'
WHERE NOT EXISTS (SELECT 1 FROM incident_events WHERE incident_id = '11111111-1111-1111-1111-111111111111' AND description LIKE 'Analyst assigned%');

INSERT INTO incident_assets (incident_id, asset_id) VALUES
  ('11111111-1111-1111-1111-111111111111', 'a1111111-1111-1111-1111-111111111111'),
  ('11111111-1111-1111-1111-111111111111', 'a2222222-2222-2222-2222-222222222222')
ON CONFLICT (incident_id, asset_id) DO NOTHING;

-- CVE linkage — these IDs are confirmed present in the trained Python AI
-- knowledge base (cve_ai_engine.py / models/cve_random_forest_model.joblib).
-- CVE-2020-6240: SAP NetWeaver DoS (HIGH, CVSS 7.5, Tier 2 Human-Approved)
-- CVE-2021-47048: additional CVE for multi-CVE mitigation plan testing
INSERT INTO incident_cves (incident_id, cve_id) VALUES
  ('11111111-1111-1111-1111-111111111111', 'CVE-2020-6240'),
  ('11111111-1111-1111-1111-111111111111', 'CVE-2021-47048')
ON CONFLICT (incident_id, cve_id) DO NOTHING;

-- Seed Mitigation Plan & Tasks for INC-1042
INSERT INTO mitigation_plans (id, incident_id, tenant_id, version, status, summary) VALUES
  ('p1111111-1111-1111-1111-111111111111', '11111111-1111-1111-1111-111111111111', 'acme-tenant', 1, 'active', 'Multi-horizon containment and vulnerability remediation for lateral movement breach')
ON CONFLICT (id) DO NOTHING;

INSERT INTO mitigation_tasks (id, plan_id, tenant_id, horizon, title, description, tier, status, blast_radius, cve_id) VALUES
  ('t1111111-1111-1111-1111-111111111111', 'p1111111-1111-1111-1111-111111111111', 'acme-tenant', 'immediate', 'Isolate affected host FIN-WS-042', 'Quarantine endpoint network interface to halt lateral movement toward database server', 'Tier 2', 'pending', 'Single Workstation (FIN-WS-042)', NULL),
  ('t2222222-2222-2222-2222-222222222222', 'p1111111-1111-1111-1111-111111111111', 'acme-tenant', 'immediate', 'Revoke exposed user and administrative credentials', 'Terminate active session tokens for compromised user accounts', 'Tier 1', 'completed', 'User Sessions', NULL),
  ('t3333333-3333-3333-3333-333333333333', 'p1111111-1111-1111-1111-111111111111', 'acme-tenant', 'short_term', 'Deploy vendor patch for CVE-2020-6240', 'Apply SAP Security Notes to resolve NetWeaver DoS vulnerability', 'Tier 2', 'pending', 'Finance Subnet Application Servers', 'CVE-2020-6240'),
  ('t4444444-4444-4444-4444-444444444444', 'p1111111-1111-1111-1111-111111111111', 'acme-tenant', 'long_term', 'Implement zero-trust microsegmentation', 'Enforce strict firewall ACLs between general workstations and financial database tier', 'Tier 2', 'pending', 'Entire Finance Zone', NULL)
ON CONFLICT (id) DO NOTHING;

-- Seed Approval Token for Task t1111111 (Tier 2 Action awaiting distinct human sign-off)
INSERT INTO approval_tokens (
  id, tenant_id, task_id, action_type, tier, status, requested_by, approved_by, blast_radius, model_confidence, expires_at
) VALUES (
  'tok11111-1111-1111-1111-111111111111',
  'acme-tenant',
  't1111111-1111-1111-1111-111111111111',
  'isolate_host',
  'Tier 2',
  'pending',
  'dev-analyst',
  NULL,
  'Workstation FIN-WS-042 (Finance Subnet)',
  0.96,
  now() + interval '24 hours'
) ON CONFLICT (id) DO NOTHING;

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
  ('cl111111-1111-1111-1111-111111111111', 'ea111111-1111-1111-1111-111111111111', 'acme-tenant', 'take_safety_snapshot', 'Tier 1', NULL, 'succeeded', 'Snapshot snap-finws042-baseline captured successfully (file integrity + routing table).', 'system-air'),
  ('cl222222-2222-2222-2222-222222222222', 'ea111111-1111-1111-1111-111111111111', 'acme-tenant', 'block_ip 198.51.100.4', 'Tier 1', NULL, 'succeeded', 'Host firewall rule added: DROP IN/OUT 198.51.100.4. Verified reversible.', 'system-air')
ON CONFLICT (id) DO NOTHING;

-- Seed Hash-Chained Audit Trail (Genesis block and initial chained event)
INSERT INTO hash_chain_audit (
  id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash
) VALUES
  ('hc000000-0000-0000-0000-000000000000', 'acme-tenant', 'GENESIS', 'system-init', '{"msg":"ShieldDesk Hash Chain Genesis"}'::jsonb, '0000000000000000000000000000000000000000000000000000000000000000', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
  ('hc111111-1111-1111-1111-111111111111', 'acme-tenant', 'TOKEN_REQUEST', 'dev-analyst', '{"action":"isolate_host","host":"FIN-WS-042","tier":"Tier 2"}'::jsonb, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'a1f8c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b899')
ON CONFLICT (id) DO NOTHING;



