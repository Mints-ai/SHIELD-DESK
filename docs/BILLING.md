# ShieldDesk — Enterprise Billing & Subscription Architecture

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Code Reference:** `src/lib/billing/plans.ts`, `src/lib/billing/stripeWebhook.ts`, `src/lib/billing/metering.ts`  
**Payment Gateway:** Stripe API (v2023-10-16+)

---

## 1. Overview & Tiers

ShieldDesk provides a tiered SaaS subscription model with built-in metered usage for endpoints, data retention, and AI copilot investigations.

### Subscription Plans Matrix

| Plan Tier | Max Endpoints | Retention | SSO / SCIM | AI Gateway | Support SLA | Target Audience |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Starter** | 25 | 14 days | No | Community Models | 48h Email | Small Security Teams / Startups |
| **Pro** | 250 | 90 days | Google / MS OIDC | Gemini 1.5 Pro, Claude | 12h Priority | Mid-Market Security Operations |
| **Enterprise** | Unlimited | 365+ days | SAML 2.0 & SCIM 2.0 | Multi-Provider + BYOK | 1h Dedicated SOC | Regulated Enterprises & MSSPs |

---

## 2. Stripe Webhook Lifecycle

Inbound webhooks are received at `/api/billing/webhook` and processed securely via `StripeWebhookHandler` in `src/lib/billing/stripeWebhook.ts`.

```
[Stripe Cloud] 
      | (HTTPS POST with stripe-signature header)
      v
[/api/billing/webhook]
      |
      +---> [Signature Verification: constructEvent(body, sig, secret)]
      |     (Fails closed with 400 if signature invalid or timestamp drift > 300s)
      |
      +---> [Event Dispatcher]
            |
            +-- 'checkout.session.completed'   --> Provision tenant, bind stripe_customer_id
            +-- 'customer.subscription.updated' --> Update plan tier, recalculate seat quotas
            +-- 'customer.subscription.deleted' --> Mark subscription cancelled, trigger grace period
            +-- 'invoice.payment_succeeded'    --> Reset monthly quota counters, renew license
            +-- 'invoice.payment_failed'       --> Set tenant status to PAST_DUE, send dunning notice
```

---

## 3. Usage Metering & Quota Enforcement

Metering is calculated in real-time via `UsageMeter` (`src/lib/billing/metering.ts`):
- **Active Endpoints:** Count of agents transmitting heartbeats within the last 15 minutes.
- **AI Copilot Invocations:** Daily query count tracked in Redis / database counters.
- **Evidence Storage:** Byte volume of encrypted evidence bundles in the vault.

When an endpoint exceeds its plan quota:
1. **Warning Threshold (90%):** Banner notifications displayed in UI; email sent to tenant billing admin.
2. **Hard Cap (100%):** Subsequent agent enrollments are rejected with `HTTP 402 Payment Required` unless overage billing is explicitly enabled. Existing agents continue operating without disruption.

---

## 4. Dunning, Delinquency & Grace Periods

1. **Payment Failure:** Immediate retry schedule via Stripe Smart Retries. Tenant state set to `PAST_DUE`.
2. **Grace Period (14 Days):** Full security operations, telemetry ingestion, and alert notifications remain active. Remediation and automated actions continue unimpeded.
3. **Suspension (Day 15+):** Tenant shifts to `SUSPENDED` mode. Dashboard becomes read-only; automated remediations require manual confirmation; agent telemetry buffered locally.
4. **Data Purge (Day 60+):** Terminated tenant data enters the GDPR-compliant data destruction pipeline.
