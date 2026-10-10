# ShieldDesk™ Commercial Billing, Stripe Pipeline & Licensing Audit

**Audit Date:** 2026-10-10  
**Target Release:** Commercial Billing & Licensing GA  
**Repository:** [https://github.com/Mints-ai/SHIELD-DESK](https://github.com/Mints-ai/SHIELD-DESK)  
**Website:** [https://shielddesk.mintsglobal.ae/](https://shielddesk.mintsglobal.ae/)  
**Lead Auditor / Role:** Principal Engineer, Application Security Engineer, Stripe Billing Architect  
**Core Principle:** PROVE BEFORE YOU ACT.

---

## 1. Executive Summary & Audit Baseline

ShieldDesk is an autonomous SOC and remediation platform. An initial foundation for licensing and billing was established in previous phases (`src/lib/billing/*`, `src/lib/licensing/*`, `tests/*`). However, critical commercial, architectural, and security gaps currently prevent safe self-service purchasing, reliable Stripe Checkout, durable webhook reconciliation, and air-gapped customer-hosted licensing.

### Baseline Environment Inspection
- **Git Branch:** `main` (clean working tree at commit `c31744b`)
- **Node & Next.js:** Node v21.7.2, Next.js 16.3.5 (Turbopack)
- **Baseline Test Suite:** 379 tests passing, 0 failing, 1 skipped across 17 test suites (total 380 tests)
- **Database:** Supabase PostgreSQL pooler (`aws-0-ap-south-1.pooler.supabase.com:6543/postgres`) live and responsive; 34 public tables existing in active schema.
- **Stripe SDK Status:** The official `stripe` package was missing from `package.json` dependencies (now installed `stripe@^17.7.0`).

---

## 2. Current Implementation vs. Requirements Analysis

### 2.1 Existing Modules & Assets

| Module / File | Current Responsibility | Reusability / Notes |
| :--- | :--- | :--- |
| `src/lib/billing/plans.ts` | Plan definitions, in-memory mock subscriptions, quota evaluation (`canEnrollEndpoint`, `evaluateQuotaStatus`), tier updates | **Reuse & Refactor**: Contains in-memory fallback with `acme-tenant` default. Plan pricing/quotas lack Stripe Price ID mappings and annual billing intervals. |
| `src/lib/billing/licenses.ts` | Commercial license token issuance and verification | **Refactor**: Uses symmetric HMAC-SHA256 with fallback to `SHIELDDESK_SESSION_SECRET` or dev key. Stores and exposes raw license key string. Needs peppered hash digests for lookup and asymmetric signing keys for offline verification. |
| `src/lib/billing/entitlements.ts` | Server-side gate `EntitlementService.require(...)`, signed offline entitlement cache, feature gates | **Reuse & Enhance**: Excellent core logic. Needs binding to real database-backed license records rather than purely in-memory map. |
| `src/lib/billing/metering.ts` | Usage counters (`active_endpoints`, `telemetry_bytes`, `remediations_executed`, `ai_tokens_consumed`) | **Reuse & Enhance**: Currently stored in `MOCK_USAGE_STORE` in-memory Map. Needs database persistence hooks. |
| `src/lib/billing/stripeWebhook.ts` | Ingests Stripe webhooks, HMAC signature verification, in-memory event deduplication | **Major Overhaul**: Signature check didn't use official Stripe SDK `stripe.webhooks.constructEvent()`; event deduplication used in-memory `Map` rather than PostgreSQL durable inbox with transactional leasing. |
| `src/lib/licensing/licenseActivation.ts` | Agent installation binding (`tenantId`, `installationId`, `deviceIdentity`, certificate fingerprint) | **Reuse & Upgrade**: Contains in-memory state map fallback. Lacks cryptographic challenge-response proof of possession and transactional activation quota locking. |
| `src/app/api/billing/route.ts` | `GET` and `POST` for billing tier info, checkout order creation, upgrade confirmation | **Critical Security Flaw**: Contains synthetic checkout generator (`create_checkout_order`) and unverified client-driven upgrade path (`confirm_upgrade`). Must be replaced with real Stripe Checkout Sessions and Customer Portal sessions. |
| `src/app/api/billing/webhook/route.ts` | Handles Razorpay & Stripe webhooks | **Critical Flaw**: Contains signature verification bypass for `NODE_ENV === "test"`. Must enforce strict raw body signature verification and durable inboxing. |
| `src/app/api/v1/billing/licenses/route.ts` | GET/POST for license state and activation | **Vulnerability**: Reads `tenantId` from client query params/body and defaults to `"acme-tenant"`. Must derive tenant strictly from authenticated session. |
| `src/app/api/v1/licenses/[operation]/route.ts` | Agent license validate, activate, deactivate, heartbeat | **Reuse & Tighten**: Missing challenge-based proof and tenant-isolated authorization checks. |

---

## 3. Findings & Implementation Gaps (Severity Matrix)

### Finding 1: Unverified Client-Driven Plan Upgrades (CRITICAL)
- **Location:** `src/app/api/billing/route.ts:98-116`
- **Issue:** The `confirm_upgrade` action accepted arbitrary client-submitted `paymentId` and `orderId`, and immediately called `updateTenantSubscription(session.tenantId, targetTier, ...)` without contacting Stripe or waiting for verified webhook delivery.
- **Impact:** Malicious tenants could grant themselves Enterprise subscriptions for free.
- **Remediation:** Remove `confirm_upgrade` and synthetic checkout generation. Enforce that only provider-verified webhooks or authoritative reconciliation can alter subscription tiers.

### Finding 2: Insecure Tenant Identification and Hardcoded Fallbacks (CRITICAL)
- **Location:** `src/app/api/v1/billing/licenses/route.ts:13,51`, `src/lib/billing/plans.ts:95-116`
- **Issue:** Routes accepted `req.nextUrl.searchParams.get("tenantId") || "acme-tenant"` and `body.tenantId || "acme-tenant"`.
- **Impact:** A caller could inspect or activate licenses for other organizations simply by specifying `tenantId` in the query or body.
- **Remediation:** Remove all hardcoded `"acme-tenant"` fallbacks from production execution paths. Require `getSessionFromRequest(req)` and strictly bind all operations to `session.tenantId`.

### Finding 3: Raw License Key Storage & Symmetric Shared Secret Fallback (HIGH)
- **Location:** `src/lib/billing/licenses.ts:24-34`
- **Issue:** License generation used HMAC with `process.env.SHIELDDESK_LICENSE_SECRET || process.env.SHIELDDESK_SESSION_SECRET || "shielddesk_commercial_license_dev_key"`. License tokens were stored in raw form in the database.
- **Impact:** Compromise of database reveals active license keys; reusing session secret compromises license validation; symmetric signing prevents safe distribution of public verification keys to customer-hosted air-gapped instances.
- **Remediation:** Store only HMAC/SHA-256 keyed digests and display prefixes (e.g. `SD-PRO-****-9F2B`). Use asymmetric keypairs (Ed25519 / RSA) with Key ID headers for license verification and signed entitlement tokens. Separate pepper from signing secret.

### Finding 4: In-Memory Webhook Deduplication and Signature Bypass (HIGH)
- **Location:** `src/lib/billing/stripeWebhook.ts:21-22,98`, `src/app/api/billing/webhook/route.ts:54-57`
- **Issue:** Webhook events were deduplicated in a process-local `Map<string, StripeEventRecord>`. Upon server restart or multi-instance deployment, duplicate Stripe events would be reprocessed. Also, `NODE_ENV === "test"` bypassed signature validation entirely.
- **Impact:** Inconsistent billing state, replay attacks, duplicate processing on pod restarts.
- **Remediation:** Maintain a durable PostgreSQL `stripe_webhook_events` table with unique constraint on `stripe_event_id`, transactional leasing (`status = 'processing'`), retry counts, and dead-letter handling. Eliminate production signature bypasses.

### Finding 5: Discrepant Plan Catalogues (MEDIUM)
- **Location:** `docs/BILLING.md` vs `src/lib/billing/plans.ts` vs `shielddesk.mintsglobal.ae`
- **Issue:** `docs/BILLING.md` listed Starter (25 endpoints), Pro (250 endpoints), Enterprise (Unlimited). `src/lib/billing/plans.ts` listed Community (5 endpoints, $0), Pro (100 endpoints, $499), Enterprise (10000 endpoints, $1999). Website listed Community (5 endpoints, $0), Pro ($39/mo annual or $49/mo monthly, 100 endpoints), Enterprise (Custom/Unlimited).
- **Remediation:** Consolidate into a single canonical server-side catalogue in `src/lib/billing/catalog.ts` and expose via `GET /api/v1/plans`. Map each tier/interval to environment-configured Stripe Price IDs (`STRIPE_PRICE_PRO_MONTHLY`, `STRIPE_PRICE_PRO_ANNUAL`, etc.).

### Finding 6: Missing Customer Checkout, Invoicing & Licensing UI (MEDIUM)
- **Location:** Frontend routes in `src/app`
- **Issue:** No customer-facing billing management portal existed for customers to view active subscriptions, launch Stripe checkout, review invoices, manage license keys, or track node activations.
- **Remediation:** Implement responsive, premium UI pages for `/pricing`, `/billing` (customer portal), `/checkout/success`, and `/checkout/cancel`.

---

## 4. Database Schema Migration Plan (Phase 4)

We will introduce migration `db/migrations/phase_m_commercial_licensing_stripe.sql` containing:
1. `billing_customers`: Internal ID, tenant ID (UNIQUE), Stripe customer ID (UNIQUE), email, metadata.
2. `product_catalog_prices`: Plan ID, tier, interval (month/year), currency, Stripe Price ID, active status.
3. `checkout_attempts`: Internal checkout ID, tenant ID, initiating user ID, Stripe checkout session ID, plan ID, interval, status (`pending`, `completed`, `expired`), idempotency key.
4. `tenant_subscriptions`: Enhanced with `stripe_subscription_id`, `stripe_customer_id`, `tier`, `billing_interval`, `status`, `current_period_start`, `current_period_end`, `cancel_at_period_end`, `canceled_at`.
5. `subscription_status_history`: Historical transition ledger for audit.
6. `invoices`: Internal ID, tenant ID, subscription ID, Stripe invoice ID, invoice number, amount due, amount paid, status, period dates, PDF URL, hosted URL.
7. `product_licenses`: Internal license ID, tenant ID, subscription ID, license key digest, display prefix/suffix, tier, status, issued at, expires at, grace period days, signing key ID, revocation details, replaced license ID.
8. `license_activations`: Enhanced activation tracking with challenge-based proof, platform, version, heartbeat timestamps, activation state.
9. `stripe_webhook_events`: Durable inbox with `stripe_event_id` (UNIQUE), `event_type`, `payload`, `status` (`pending`, `processing`, `processed`, `failed`), `retry_count`, `lease_expires_at`, `error_message`.
10. `notification_outbox`: Transactional outbox for provisioning notifications and webhooks.

---

## 5. Staged Implementation Roadmap

- [x] **Phase 0:** Baseline test suite run, database connectivity verification, live website audit, documentation of findings.
- [ ] **Phase 1:** Canonical product catalogue with Stripe Price ID mappings (`src/lib/billing/catalog.ts`, `GET /api/v1/plans`).
- [ ] **Phase 2:** Official Stripe client, authenticated checkout session generator (`POST /api/v1/billing/checkout-sessions`), customer portal session generator (`POST /api/v1/billing/portal-sessions`), removal of synthetic order endpoints.
- [ ] **Phase 3:** Durable Stripe webhook inbox with SDK-validated signatures, transactional deduplication, and lifecycle handlers (`checkout.session.completed`, `customer.subscription.*`, `invoice.*`).
- [ ] **Phase 4:** Additive PostgreSQL migration script and database schema execution.
- [ ] **Phase 5:** License Service APIs with cryptographic key digest lookup, challenge-based activation, short-lived signed entitlement tokens, deactivation, and revocation.
- [ ] **Phase 6:** Subscriptions, invoices, prorated plan changes, and grace period engine.
- [ ] **Phase 7:** Frontend customer portal, pricing cards, checkout redirection, pending/success states, and license management dashboard.
- [ ] **Phase 8:** Comprehensive automated test suite (Stripe test-mode journeys, cross-tenant denial, key generation, tamper rejection, webhook idempotency, and Next.js production build).
- [ ] **Phase 9:** Documentation updates and Release Go/No-Go decision matrix.
