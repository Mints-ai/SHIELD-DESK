# Phase 3 Changelog: Multi-Tenancy Hardening & Row-Level Security (RLS)

## Overview
Enforces the Master Prompt Section 15 requirements:
1. **Authoritative Session Binding**: Tenant context is extracted strictly from the authenticated session (`SessionUser.tenant_id`) and can never be spoofed or overridden via client request body or query parameter (`enforceTenantBoundary()`).
2. **Anti-Enumeration Guard (HTTP 404)**: Cross-tenant access attempts by non-privileged callers throw `TenantResourceNotFoundError` returning HTTP 404 (Not Found), never 403 (Forbidden), preventing resource discovery or existence leaks.
3. **Database-Level Row-Level Security (RLS)**:
   - Enabled RLS on all 15 business tables in PostgreSQL.
   - Added complete PostgreSQL RLS policies in `db/schema.sql` covering `incidents`, `assets`, `chat_audit_log`, `mitigation_plans`, `mitigation_tasks`, `approval_tokens`, `endpoint_agents`, `agent_command_logs`, `agent_commands`, `hash_chain_audit`, `endpoint_certificates`, `endpoint_snapshots`, `endpoint_kill_switches`, `endpoint_enrollment_tokens`, and `endpoint_telemetry`.
   - Added `withTenantContext()` and `tenantQuery()` in `src/lib/db/index.ts` to automatically configure `app.current_tenant` and `app.user_role` within transactions for deep database-level isolation.
4. **Service Isolation**: Created `src/lib/tenancy/` and `services/tenancy/` providing unified tenancy guards, query builders, and type contracts.

## Key Changes
- `src/lib/tenancy/types.ts`: Defined `TenantContext`, `TenantResourceNotFoundError` (404), and `TenantSpoofingError` (403).
- `src/lib/tenancy/guard.ts`: Implemented `extractTenantContext`, `assertTenantAccess`, `enforceTenantBoundary`, and `buildTenantSqlFilter`.
- `src/lib/tenancy/index.ts`: Module export index.
- `services/tenancy/index.ts`: Service-layer facade.
- `src/lib/db/index.ts`: Added `withTenantContext` and `tenantQuery` for RLS variable injection.
- `db/schema.sql`: Added complete RLS enablements and policies across all tables.
- `tests/multi-tenancy-and-rls.test.ts`: Dedicated test suite verifying anti-enumeration 404, tenant spoofing rejection, and SQL filter parameterization.

## Verification
- All 21 test suites and 157 unit/integration tests passing (0 failures).
- TypeScript strict compiler check passed cleanly (0 errors).
