-- Development Seed Data (db/seed.dev.sql)
-- ONLY for local development and non-production environments.
-- Do NOT mount this file into production deployments or docker-compose.prod.yml.

INSERT INTO users (id, tenant_id, role, email) VALUES
  ('dev-analyst',   'acme-tenant', 'analyst',      'analyst@acme.corp'),
  ('dev-admin',     'acme-tenant', 'system_admin', 'admin@acme.corp'),
  ('dev-super',     'acme-tenant', 'super_admin',  'superadmin@acme.corp'),
  ('dev-responder', 'acme-tenant', 'responder',    'responder@acme.corp')
ON CONFLICT (id) DO NOTHING;

