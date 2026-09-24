-- Development Seed Data (db/seed.dev.sql)
-- ONLY for local development and non-production environments.
-- Do NOT mount this file into production deployments or docker-compose.prod.yml.

INSERT INTO users (id, tenant_id, role, email) VALUES
  ('dev-analyst', 'acme-tenant',   'user',         'analyst@acme.corp'),
  ('dev-admin',   'acme-tenant',   'system_admin', 'admin@acme.corp'),
  ('dev-other',   'globex-tenant', 'user',         'secops@globex.corp')
ON CONFLICT (id) DO NOTHING;
