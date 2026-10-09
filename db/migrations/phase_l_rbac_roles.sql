-- Migration: Expand users.role CHECK constraint to support all 4 RBAC roles
-- Replaces the previous ('system_admin','super_admin','user') constraint
-- with the full role set: system_admin, super_admin, responder, analyst.
--
-- Run this on any existing DB where the users table was already created.

-- 1. Drop the old CHECK constraint (PostgreSQL requires knowing its name first)
DO $$
DECLARE
  constraint_name text;
BEGIN
  SELECT conname INTO constraint_name
  FROM pg_constraint
  WHERE conrelid = 'users'::regclass
    AND contype = 'c'
    AND pg_get_constraintdef(oid) LIKE '%role%';

  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', constraint_name);
  END IF;
END;
$$;

-- 2. Add the updated CHECK constraint with all 4 target roles
ALTER TABLE users
  ADD CONSTRAINT users_role_check
  CHECK (role IN ('system_admin', 'super_admin', 'responder', 'analyst'));

-- 3. Migrate existing 'user' role records to 'analyst'
--    (the old dev-seed used 'user' for analyst personas)
UPDATE users SET role = 'analyst' WHERE role = 'user';

-- 4. Migrate any old 'viewer' / 'auditor' records to 'analyst' (read-only mapped to analyst)
UPDATE users SET role = 'analyst' WHERE role IN ('viewer', 'auditor');

-- 5. Upsert the 4 canonical dev personas
INSERT INTO users (id, tenant_id, role, email) VALUES
  ('dev-analyst',   'acme-tenant', 'analyst',      'analyst@acme.corp'),
  ('dev-admin',     'acme-tenant', 'system_admin', 'admin@acme.corp'),
  ('dev-super',     'acme-tenant', 'super_admin',  'superadmin@acme.corp'),
  ('dev-responder', 'acme-tenant', 'responder',    'responder@acme.corp')
ON CONFLICT (id) DO UPDATE
  SET role      = EXCLUDED.role,
      email     = EXCLUDED.email,
      tenant_id = EXCLUDED.tenant_id;

-- 6. Remove old dev-other (Globex) persona if it exists
DELETE FROM users WHERE id = 'dev-other';
