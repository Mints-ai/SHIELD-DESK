# ShieldDesk™ — Commercial Stripe Billing & Subscription Architecture

**Document Version:** 2.0.0-commercial  
**Target Release:** ShieldDesk Commercial GA  
**Code References:**  
- Product Catalogue: `src/lib/billing/catalog.ts`
- Checkout & Customer Portal: `src/lib/billing/checkoutService.ts`
- Stripe SDK Client: `src/lib/billing/stripeClient.ts`
- Durable Webhook Inbox & Reconciliation: `src/lib/billing/stripeWebhook.ts`
- Billing Route Handlers: `src/app/api/v1/billing/*`
- Legacy Settlement Route: `src/app/api/billing/webhook/route.ts`
- Customer Billing Dashboard: `src/app/dashboard/billing/page.tsx`
- Pricing Pages: `src/app/pricing/page.tsx`

---

## 1. Canonical Product Catalogue & Pricing Matrix

ShieldDesk implements a server-authoritative product catalogue (`src/lib/billing/catalog.ts`). Client applications cannot submit arbitrary price amounts or unverified Stripe Price IDs.

| Plan ID | Display Name | Monthly Price | Annual Price (20% Off) | Max Endpoints | Max Users | Retention | Key Commercial Entitlements |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `community` | **Community Pilot** | Free ($0) | Free ($0) | 5 | 2 | 7 days | Telemetry ingest, real-time detection, community rules, Discord/Slack webhooks. |
| `professional` | **Professional SOC** | $499 / mo | $399 / mo ($4,788/yr) | 250 | 15 | 90 days | Tier 1 automated containment, SIEM connectors, custom YARA/detection rules, standard SLA. |
| `enterprise` | **Enterprise Defense** | $1,999 / mo | $1,599 / mo ($19,188/yr) | 10,000 | Unlimited | 365 days | Tier 2 & 3 governed remediations, immutable evidence vault, multi-tenant RLS, 24/7 dedicated SOC SLA. |

---

## 2. Stripe Checkout Lifecycle & Security Invariants

### 2.1 Checkout Session Initiation (`POST /api/v1/billing/checkout-sessions`)
1. **Authentication & RBAC:** Strictly requires an authenticated billing administrator (`system_admin`, `super_admin`, or `billing_admin`).
2. **Server-Side Price Resolution:** Maps `planId` and `billingInterval` directly to server-configured Stripe Price IDs. Tampered or client-specified price amounts are rejected.
3. **Durable Attempt Recording:** Before contacting Stripe, a durable `checkout_attempts` row is inserted into PostgreSQL with a unique correlation key and idempotency key.
4. **Subscription Mode:** Initiates a Stripe Checkout session in `mode: "subscription"`, associating the authenticated Stripe Customer ID, tenant metadata, and validated redirect URLs.
5. **No Premature Upgrades:** Creating a checkout session NEVER upgrades the tenant. The tenant remains on their prior tier until authoritative payment webhook verification.

### 2.2 Success Redirect & Polling (`GET /api/v1/billing/checkout-status`)
- When Stripe redirects the customer to `/checkout/success?attemptId=...`, the UI displays a pending status while polling `/api/v1/billing/checkout-status`.
- **Security Invariant:** Polling inspects durable database state; polling cannot grant access.
- Cross-tenant status queries are strictly denied (`400/404`).

---

## 3. Durable Webhook Inbox & Reconciliation Pipeline

Inbound webhooks are received at `/api/billing/webhook` and processed via `StripeWebhookManager` (`src/lib/billing/stripeWebhook.ts`).

```
[Stripe Cloud POST]
       |
       v
[/api/billing/webhook]
       |
       +---> [1. Raw Request Body Signature Check]
       |     crypto.timingSafeEqual with STRIPE_WEBHOOK_SECRET. Fails closed with 401.
       |
       +---> [2. Durable Inbox Ingestion (stripe_webhook_events)]
       |     INSERT INTO stripe_webhook_events ... ON CONFLICT (stripe_event_id) DO NOTHING
       |     If duplicate -> Return HTTP 200 { isDuplicate: true }
       |
       +---> [3. Atomic Lease & Queue Worker]
       |     UPDATE stripe_webhook_events SET status = 'processing', lease_expires_at = NOW() + 2min
       |
       +---> [4. Event Execution & State Transitions]
             |-- 'checkout.session.completed': Provision subscription, bind billing customer, issue commercial license
             |-- 'customer.subscription.updated': Apply prorated upgrades / effective downgrades
             |-- 'customer.subscription.deleted': Downgrade to Community, suspend paid entitlements
             |-- 'invoice.paid': Record invoice PDF/URL, reset billing period, renew license
             |-- 'invoice.payment_failed': Trigger 14-day delinquency grace period, notify billing admin
             |-- 'charge.refunded': Suspend subscription according to approved refund policy
```

---

## 4. Subscriptions, Invoices, Plan Changes & Grace Periods

### 4.1 Plan Upgrades (`POST /api/v1/billing/change-plan`)
- Upgrades apply Stripe proration policies (`proration_behavior: "create_prorations"`).
- Target tier limits and entitlements unlock immediately upon provider confirmation.
- State transitions are recorded in `subscription_status_history`.

### 4.2 Plan Downgrades
- Downgrades take effect at the end of the current billing period to protect customer data.
- Quotas (endpoints, retention, users) are evaluated before downgrade enforcement to prevent silent telemetry loss.

### 4.3 Cancellations (`POST /api/v1/billing/cancel`)
- Default behavior: Schedules cancellation at billing period end (`cancel_at_period_end: true`).
- Immediate cancellation: Explicitly supported for emergency decommission, immediately revoking paid entitlements and reverting tenant to `community`.

### 4.4 14-Day Payment Failure Grace Period
- If an invoice payment fails (`invoice.payment_failed`), the subscription transitions to `past_due`.
- A 14-day grace period is granted during which security monitoring, agent heartbeats, and audit logs continue without interruption.
- Automated containment or new endpoint enrollments are restricted until payment is reconciled.
