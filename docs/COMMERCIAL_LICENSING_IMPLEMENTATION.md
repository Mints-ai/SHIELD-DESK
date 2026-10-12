# ShieldDesk™ Commercial Licensing, Stripe Billing & Customer Purchase Implementation

**Version:** 1.0.0-commercial  
**Status:** IMPLEMENTED & VERIFIED  
**Date:** October 2026  
**Engineering Lead:** DevSecOps, Billing & Licensing Core Team  
**Repository:** [https://github.com/Mints-ai/SHIELD-DESK](https://github.com/Mints-ai/SHIELD-DESK)  
**Website:** [https://shielddesk.mintsglobal.ae/](https://shielddesk.mintsglobal.ae/)  

---

## 1. Executive Summary & Mission Scope

ShieldDesk™ provides enterprise autonomous Security Operations Center (SOC) defense. To transition from pilot programs to global commercial scale, a complete, cryptographically verified commercial purchasing, Stripe billing, and customer-hosted licensing system has been engineered.

### Core Architectural Pillars
1. **Canonical Product Catalogue (`src/lib/billing/catalog.ts`):** Single authoritative definition of plans (`community`, `professional`, `enterprise`), intervals (`month`, `year`), currency mappings, endpoint/user quotas, and feature flags. Client-supplied Price IDs or tamper amounts are strictly rejected.
2. **Durable Stripe Checkout (`src/lib/billing/checkoutService.ts`):** Server-side session generation bound to authenticated tenants with durable `checkout_attempts` tracking. Polling or checkout redirect URLs cannot grant unearned paid entitlements.
3. **Durable Webhook Inbox & Reconciliation (`src/lib/billing/stripeWebhook.ts`):** Atomic leasing, idempotent event deduplication, retry queues, invoice recording, and transactional provisioning via PostgreSQL `stripe_webhook_events`.
4. **Zero-Raw-Secret Licensing Service (`src/lib/billing/licenses.ts` & `src/lib/licensing/licenseActivation.ts`):** High-entropy cryptographic license keys (`192-bit` entropy), peppered SHA-256 digests (`hashLicenseKey`), safe display masks (`SD-PRO-****-B24F`), asymmetric offline entitlement tokens (`issueAsymmetricEntitlementToken`), and transactional seat cap enforcement.
5. **Customer Portal & Dashboard (`src/app/pricing`, `src/app/dashboard/billing`, `src/app/checkout/*`):** Public pricing comparisons, Stripe customer portal launchers, real-time quota gauges, downloadable invoices, and license management.

---

## 2. Canonical Product Catalogue

The authoritative product matrix is configured in `src/lib/billing/catalog.ts` and exposed publicly via `GET /api/v1/plans`:

| Tier | Plan Name | Monthly Price (USD) | Annual Price (USD - 20% Off) | Max Endpoints | Max Users | Retention | Key Entitlements |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Community** | Community Pilot | $0 | $0 | 5 | 2 | 7 days | Telemetry ingest, real-time detection, community rules, Discord/Slack alerts. |
| **Professional** | Professional SOC | $499 / mo | $399 / mo ($4,788 billed annually) | 250 | 15 | 90 days | Tier 1 automated containment, SIEM connectors, custom YARA/detection rules, standard SLA. |
| **Enterprise** | Enterprise Defense | $1,999 / mo | $1,599 / mo ($19,188 billed annually) | 10,000 | Unlimited | 365 days | Tier 2 & 3 governed remediations, immutable evidence vault, multi-tenant RLS, 24/7 dedicated SOC SLA. |

---

## 3. Customer Purchase Journeys

### 3.1 Hosted SaaS Customer Journey
1. **Explore:** Customer visits [https://shielddesk.mintsglobal.ae/pricing](https://shielddesk.mintsglobal.ae/pricing), compares plan features and quotas, and toggles Monthly/Annual billing.
2. **Authenticate:** Customer signs up or logs into their tenant command center.
3. **Select:** Customer selects Professional or Enterprise plan and clicks **Upgrade to Pro** / **Deploy Enterprise**.
4. **Checkout Session:** Browser calls `POST /api/v1/billing/checkout-sessions`. The server resolves the authoritative Stripe Price ID, records a durable `checkout_attempts` record, and returns the Stripe Checkout URL.
5. **Stripe Checkout:** Customer completes payment on Stripe-hosted checkout (Credit Card, ACH, Wire).
6. **Redirect & Verification:** Stripe redirects customer to `/checkout/success?session_id=cs_...`. The page enters a pending state while polling `GET /api/v1/billing/checkout-status`.
7. **Authoritative Webhook Settlement:** Stripe emits `checkout.session.completed`. The durable webhook inbox cryptographically verifies the raw payload signature, registers the customer, updates `tenant_subscriptions` to `active`, issues a commercial license, and commits an outbox event.
8. **Instant SaaS Access:** The customer dashboard (`/dashboard/billing`) immediately displays active status, updated quotas, and unlocks paid features. Control-plane source code is never exposed or downloaded.

### 3.2 Customer-Hosted (Self-Hosted) Deployment Journey
1. **Purchase:** Customer purchases Customer-Hosted SKU via Stripe Checkout.
2. **License Reveal:** Upon verified payment webhook processing, the customer navigates to `/dashboard/billing` and retrieves their newly issued high-entropy license key (revealed securely once with recovery workflows).
3. **Download Package:** Customer downloads authorized private ShieldDesk container images / packages (`ghcr.io/mints-ai/shielddesk-agent`).
4. **Activation:** During agent installation, the agent provides installation ID, device identity, X.509 certificate, and calls `POST /api/v1/licenses/activate`.
5. **Signed Entitlement Token:** The licensing service verifies the peppered hash in `product_licenses`, checks transactional activation limits (`active_activations < max_endpoints`), and issues an asymmetric, short-lived signed entitlement token.
6. **Periodic Refresh:** Running agents call `POST /api/v1/licenses/refresh` every 24 hours. If internet connectivity is temporarily interrupted, the agent safely executes under a configurable 14-day offline grace period.
7. **Deactivation & Revocation:** Administrators can deactivate individual edge installations (`POST /api/v1/licenses/activations/:id/deactivate`) to reclaim seats or administratively revoke keys (`POST /api/v1/licenses/:id/revoke`) in security incidents.

---

## 4. PostgreSQL Database Schema & Migration

Migration `db/migrations/phase_m_commercial_licensing_stripe.sql` creates 10 enterprise tables:

```
+----------------------------------------------------------------------------------------------------+
|                                    SHIELDDESK COMMERCIAL SCHEMA                                    |
+----------------------------------------------------------------------------------------------------+
|  1. billing_customers             (id, tenant_id, stripe_customer_id, billing_email, timestamps)     |
|  2. product_catalog_prices        (id, plan_id, interval, currency, stripe_price_id, amount_cents)    |
|  3. checkout_attempts             (id, tenant_id, user_id, session_id, plan_id, status, timestamps)  |
|  4. tenant_subscriptions          (id, tenant_id, stripe_sub_id, tier, status, period_end, cancel)   |
|  5. subscription_status_history   (id, sub_id, tenant_id, from_status, to_status, reason, payload)  |
|  6. invoices                      (id, tenant_id, stripe_inv_id, amount_due, amount_paid, pdf_url)  |
|  7. product_licenses              (id, tenant_id, license_key_hash, prefix, suffix, max_endpoints)  |
|  8. license_activations           (id, license_id, tenant_id, installation_id, device_id, state)    |
|  9. stripe_webhook_events         (id, event_type, status, retry_count, lease_expires_at, payload)   |
| 10. notification_outbox           (id, tenant_id, topic, payload, status, created_at)               |
+----------------------------------------------------------------------------------------------------+
```

All customer-facing tables enforce PostgreSQL Row-Level Security (RLS) scoping queries by `tenant_id = current_setting('app.current_tenant_id', true)`.

---

## 5. API Reference & Contract Specifications

### 5.1 Public Catalogue
- **`GET /api/v1/plans`**
  - **Auth:** None (Public).
  - **Response (200):** `{ success: true, plans: [...], generatedAt: string }`

### 5.2 Stripe Billing Operations
- **`POST /api/v1/billing/checkout-sessions`**
  - **Auth:** Bearer Token (Role: `system_admin`, `super_admin`, `billing_admin`).
  - **Request:** `{ planId: "professional"|"enterprise", billingInterval: "month"|"year", currency?: "USD", deploymentType?: "hosted_saas"|"customer_hosted" }`
  - **Response (200):** `{ success: true, attemptId: string, sessionId: string, checkoutUrl: string, plan: string, interval: string }`
- **`GET /api/v1/billing/checkout-status?attemptId=...`**
  - **Auth:** Bearer Token (Authenticated Tenant).
  - **Response (200):** `{ success: true, tenantId: string, status: "pending"|"completed"|"failed", isProvisioned: boolean, currentSubscription: object }`
- **`POST /api/v1/billing/portal-sessions`**
  - **Auth:** Bearer Token (Role: `billing_admin`, `system_admin`).
  - **Response (200):** `{ success: true, portalUrl: string }`
- **`GET /api/v1/billing/subscription`**
  - **Auth:** Bearer Token.
  - **Response (200):** `{ success: true, subscription: { tier, name, status, enrolledEndpoints, maxEndpoints, maxUsers, retentionDays, features }, entitlements: { state, graceUntil } }`
- **`POST /api/v1/billing/change-plan`**
  - **Auth:** Privileged Bearer Token.
  - **Request:** `{ targetTier: "professional"|"enterprise", billingInterval: "month"|"year" }`
  - **Response (200):** `{ success: true, subscription: { tier, status, currentPeriodEnd } }`
- **`POST /api/v1/billing/cancel`**
  - **Auth:** Privileged Bearer Token.
  - **Request:** `{ immediate?: boolean, reason?: string }`
  - **Response (200):** `{ success: true, message: string, immediate: boolean, currentPeriodEnd: string }`
- **`GET /api/v1/billing/invoices`**
  - **Auth:** Bearer Token.
  - **Response (200):** `{ success: true, invoices: [{ invoiceId, invoiceNumber, amountDue, amountPaid, currency, status, pdfUrl, hostedInvoiceUrl, periodStart, periodEnd }] }`

### 5.3 Licensing & Activation Service
- **`POST /api/v1/licenses/activate`**
  - **Request:** `{ licenseKey: string, installationId: string, deviceIdentity: string, certificatePem: string, platform?: string, productVersion?: string }`
  - **Response (200):** `{ success: true, activation: { id, tenantId, installationId, state: "ACTIVE", entitlementToken: string, licenseExpiresAt: string } }`
- **`POST /api/v1/licenses/refresh`**
  - **Request:** `{ licenseKey: string, installationId: string, deviceIdentity: string, certificatePem: string }`
  - **Response (200):** `{ success: true, entitlementToken: string, expiresAt: string, state: "ACTIVE" }`
- **`GET /api/v1/licenses/activations`**
  - **Auth:** Bearer Token (Authenticated Tenant).
  - **Response (200):** `{ success: true, activations: [{ installationId, deviceIdentity, state, activatedAt, lastHeartbeatAt }] }`
- **`POST /api/v1/licenses/activations/:id/deactivate`**
  - **Auth:** Bearer Token (Tenant Billing/System Admin).
  - **Response (200):** `{ success: true, message: "Installation deactivated successfully.", status: "DEACTIVATED" }`
- **`POST /api/v1/licenses/:id/revoke`**
  - **Auth:** System Admin / Super Admin.
  - **Request:** `{ reason: string }`
  - **Response (200):** `{ success: true, licenseId: string, status: "revoked" }`

---

## 6. Security Guarantees & Non-Negotiable Invariants

1. **Zero Raw License Storage:** The database persists only `license_key_hash = HMAC-SHA256(pepper, rawLicenseKey)` and display fragments (`SD-ENT-****-B24F`). A compromised database cannot leak usable commercial license keys.
2. **Pepper vs. Secret Separation:** The license hash pepper (`SHIELDDESK_LICENSE_PEPPER`) is distinct from the asymmetric signing keys (`SHIELDDESK_LICENSE_SECRET`). Session secret fallback is prohibited.
3. **No Signature Bypasses:** The Stripe webhook endpoint cryptographically validates `stripe-signature` against the exact raw request body. Missing or untrusted signatures fail closed with `401 Unauthorized`.
4. **Durable Webhook Deduplication:** Events are leased transactionally in PostgreSQL (`stripe_webhook_events`). Duplicate event IDs are acknowledged idempotently without double-processing.
5. **No Synthetic State or Success Redirect Trust:** Access is granted solely when Stripe emits provider-confirmed webhook events (`checkout.session.completed`, `invoice.paid`). Redirecting to `/checkout/success` grants zero elevated access.
6. **Cross-Tenant Isolation:** All APIs bind queries to the authenticated session tenant. Attempts by Tenant A to inspect, poll, or activate Tenant B's subscriptions or licenses return `400/403/404` and write tamper audit events to the immutable hash-chain ledger.
