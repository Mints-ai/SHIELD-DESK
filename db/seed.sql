-- Production baseline seeds. Dev personas are separated in db/seed.dev.sql
INSERT INTO users (id, tenant_id, role, email) VALUES
  ('system-air', 'acme-tenant', 'system_admin', 'system-air@internal.shielddesk')
ON CONFLICT (id) DO NOTHING;


-- Seed Hash-Chained Audit Trail (Genesis block)
INSERT INTO hash_chain_audit (
  id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash
) VALUES
  ('00000000-0000-0000-0000-000000000000', 'acme-tenant', 'GENESIS', 'system-init', '{"msg":"ShieldDesk Hash Chain Genesis"}'::jsonb, '0000000000000000000000000000000000000000000000000000000000000000', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
ON CONFLICT (id) DO NOTHING;


