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
