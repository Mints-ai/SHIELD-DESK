"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Shield,
  Check,
  X,
  Zap,
  ArrowRight,
  Server,
  Lock,
  Download,
  Terminal,
  Activity,
  Layers,
  Sparkles,
  HelpCircle,
  ExternalLink,
} from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";

interface PublicPlan {
  id: "community" | "professional" | "enterprise";
  name: string;
  tagline: string;
  description: string;
  deploymentModel: string;
  maxEndpoints: number;
  maxUsers: number;
  retentionDays: number;
  trialDays: number;
  trialEligible: boolean;
  supportSla: string;
  features: Record<string, boolean>;
  supportedIntegrations: string[];
  pricing: {
    month: {
      amountUSD: number;
      priceCents: number;
      interval: "month";
    };
    year: {
      amountUSD: number;
      monthlyEquivalentUSD: number;
      priceCents: number;
      interval: "year";
      savingsPercent: number;
    };
  };
}

export default function PricingPage() {
  const { activeUser } = useChat();
  const [plans, setPlans] = useState<PublicPlan[]>([]);
  const [billingInterval, setBillingInterval] = useState<"month" | "year">("year");
  const [currency, setCurrency] = useState<"USD" | "EUR" | "AED">("USD");
  const [deploymentType, setDeploymentType] = useState<"saas" | "customer-hosted">("saas");
  const [isLoadingCheckout, setIsLoadingCheckout] = useState<string | null>(null);
  const [checkoutError, setCheckoutError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/plans")
      .then((res) => res.json())
      .then((data) => {
        if (data?.plans) {
          setPlans(data.plans);
        }
      })
      .catch(() => {
        // Fallback default
      });
  }, []);

  const currencyMultiplier = currency === "EUR" ? 0.92 : currency === "AED" ? 3.67 : 1;
  const currencySymbol = currency === "EUR" ? "€" : currency === "AED" ? "AED " : "$";

  const handleLaunchCheckout = async (planId: string) => {
    if (planId === "community") {
      window.location.href = "/dashboard/billing";
      return;
    }

    setIsLoadingCheckout(planId);
    setCheckoutError(null);

    try {
      const res = await fetch("/api/v1/billing/checkout-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          planId,
          interval: billingInterval,
          currency,
          deploymentType,
          successUrl: `${window.location.origin}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
          cancelUrl: `${window.location.origin}/checkout/cancel`,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to create checkout session");
      }

      if (data.checkoutUrl) {
        window.location.href = data.checkoutUrl;
      }
    } catch (err: unknown) {
      setCheckoutError(err instanceof Error ? err.message : "Checkout error occurred");
    } finally {
      setIsLoadingCheckout(null);
    }
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="max-w-7xl mx-auto px-6 py-12 flex-1 w-full space-y-12">
        {/* Header Hero */}
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[var(--sd-pine)]/10 border border-[var(--sd-pine)]/20 text-[var(--sd-pine)] text-xs font-mono uppercase tracking-widest">
            <Sparkles className="w-3.5 h-3.5" />
            Commercial Licensing & Cloud Control Plane
          </div>
          <h1 className="text-4xl sm:text-5xl font-light tracking-tight text-[var(--sd-text)]">
            Transparent Pricing for <span className="font-semibold text-[var(--sd-wheat)]">Autonomous Defense</span>
          </h1>
          <p className="text-[14px] text-[var(--sd-text-muted)] leading-relaxed">
            Deploy ShieldDesk in our managed SOC cloud or air-gapped on your private infrastructure.
            Every plan is backed by our unyielding core invariant: <strong className="text-[var(--sd-text)]">PROVE BEFORE YOU ACT.</strong>
          </p>

          {/* Controls: Billing Interval & Currency */}
          <div className="pt-6 flex flex-wrap items-center justify-center gap-4">
            {/* Interval Toggle */}
            <div className="inline-flex items-center p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] shadow-xs">
              <button
                type="button"
                onClick={() => setBillingInterval("month")}
                className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  billingInterval === "month"
                    ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] shadow-xs"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                }`}
              >
                Monthly Billing
              </button>
              <button
                type="button"
                onClick={() => setBillingInterval("year")}
                className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
                  billingInterval === "year"
                    ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] shadow-xs"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                }`}
              >
                <span>Annual Billing</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-[var(--sd-gold)] text-[var(--sd-on-accent)] font-semibold font-mono">
                  Save 20%
                </span>
              </button>
            </div>

            {/* Currency Selector */}
            <div className="inline-flex items-center gap-1 p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-xs font-mono">
              {(["USD", "EUR", "AED"] as const).map((curr) => (
                <button
                  key={curr}
                  type="button"
                  onClick={() => setCurrency(curr)}
                  className={`px-2.5 py-1 rounded-lg transition-colors ${
                    currency === curr
                      ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                  }`}
                >
                  {curr}
                </button>
              ))}
            </div>

            {/* Deployment Model */}
            <div className="inline-flex items-center gap-1 p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-xs font-mono">
              <button
                type="button"
                onClick={() => setDeploymentType("saas")}
                className={`px-3 py-1 rounded-lg transition-colors ${
                  deploymentType === "saas"
                    ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                }`}
              >
                Hosted SaaS
              </button>
              <button
                type="button"
                onClick={() => setDeploymentType("customer-hosted")}
                className={`px-3 py-1 rounded-lg transition-colors ${
                  deploymentType === "customer-hosted"
                    ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                }`}
              >
                Customer-Hosted (Air-Gapped)
              </button>
            </div>
          </div>
        </div>

        {checkoutError && (
          <div className="max-w-md mx-auto p-3.5 rounded-xl bg-[var(--sd-danger-dim)] border border-[var(--sd-danger-border)] text-[var(--sd-danger)] text-xs text-center">
            {checkoutError}
          </div>
        )}

        {/* Pricing Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Community Card */}
          <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-7 flex flex-col justify-between shadow-xs hover:border-[var(--sd-pine)]/40 transition-all">
            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[var(--sd-pine)] font-semibold">
                  Community Pilot
                </span>
                <h3 className="text-xl font-medium text-[var(--sd-text)] mt-1">Free Evaluation</h3>
                <p className="text-xs text-[var(--sd-text-muted)] mt-1.5 leading-relaxed">
                  Ideal for homelabs, independent security researchers, and preliminary pilot evaluations.
                </p>
              </div>

              <div className="py-2 border-y border-[var(--sd-border)]">
                <div className="flex items-baseline gap-1">
                  <span className="text-3xl font-light font-mono text-[var(--sd-text)]">{currencySymbol}0</span>
                  <span className="text-xs text-[var(--sd-text-muted)]">/ forever</span>
                </div>
                <p className="text-[11px] text-[var(--sd-text-dim)] mt-0.5">Up to 5 endpoint agents included</p>
              </div>

              <ul className="space-y-2.5 text-xs text-[var(--sd-text-muted)]">
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>5 Enrolled Endpoints &amp; Fleet mTLS</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>Full SOC Incident Queue &amp; Triage</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>CrowdStrike, Defender &amp; Wazuh Ingest</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>Native YARA Engine &amp; Scanner</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>7 Days Evidence Retention</span>
                </li>
                <li className="flex items-center gap-2 text-[var(--sd-text-dim)] line-through">
                  <X className="w-4 h-4 text-[var(--sd-text-dim)] shrink-0" />
                  <span>Tier 1 Automated Remediation</span>
                </li>
              </ul>
            </div>

            <button
              onClick={() => handleLaunchCheckout("community")}
              className="mt-6 w-full py-2.5 rounded-full border border-[var(--sd-border)] sd-surface text-xs font-medium text-[var(--sd-text)] hover:bg-[var(--sd-panel-raised)] transition-colors cursor-pointer"
            >
              Start Free Pilot
            </button>
          </div>

          {/* Professional Card (Featured) */}
          <div className="rounded-2xl border-2 border-[var(--sd-pine)] bg-[var(--sd-surface)] p-7 flex flex-col justify-between shadow-lg relative">
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-[var(--sd-pine)] text-[var(--sd-on-accent)] text-[10px] font-mono uppercase tracking-wider font-semibold shadow-xs">
              Most Popular • Enterprise SOC Pro
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[var(--sd-pine)] font-semibold">
                  Professional
                </span>
                <h3 className="text-xl font-medium text-[var(--sd-text)] mt-1">ShieldDesk SOC Pro</h3>
                <p className="text-xs text-[var(--sd-text-muted)] mt-1.5 leading-relaxed">
                  Engineered for high-velocity security operations teams requiring automated containment and AI blast radius modeling.
                </p>
              </div>

              <div className="py-2 border-y border-[var(--sd-border)]">
                <div className="flex items-baseline gap-1">
                  <span className="text-3xl font-light font-mono text-[var(--sd-text)]">
                    {currencySymbol}
                    {billingInterval === "year"
                      ? Math.round(39 * currencyMultiplier)
                      : Math.round(49 * currencyMultiplier)}
                  </span>
                  <span className="text-xs text-[var(--sd-text-muted)]">
                    / mo {billingInterval === "year" ? "(billed annually)" : ""}
                  </span>
                </div>
                <p className="text-[11px] text-[var(--sd-pine)] mt-0.5">Up to 100 endpoint agents included</p>
              </div>

              <ul className="space-y-2.5 text-xs text-[var(--sd-text-muted)]">
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span className="text-[var(--sd-text)] font-medium">Up to 100 Endpoint Agents</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>AI Blast Radius &amp; Vulnerability ML Model</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>3-Horizon Structured Remediation Task Board</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>RSA-2048 Signed Command Dispatch</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>Trivy CVE &amp; Gitleaks Secrets Scanning</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>90 Days Evidence Retention</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-pine)] shrink-0" />
                  <span>Priority 4h Email Support</span>
                </li>
              </ul>
            </div>

            <button
              onClick={() => handleLaunchCheckout("professional")}
              disabled={isLoadingCheckout === "professional"}
              className="mt-6 w-full py-2.5 rounded-full bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[var(--sd-on-accent)] text-xs font-semibold shadow-xs transition-colors cursor-pointer flex items-center justify-center gap-2"
            >
              {isLoadingCheckout === "professional" ? (
                <span>Launching Stripe Checkout...</span>
              ) : (
                <>
                  <span>Select SOC Pro</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>

          {/* Enterprise Card */}
          <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-7 flex flex-col justify-between shadow-xs hover:border-[var(--sd-pine)]/40 transition-all">
            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[var(--sd-gold)] font-semibold">
                  Enterprise
                </span>
                <h3 className="text-xl font-medium text-[var(--sd-text)] mt-1">Autonomous Enterprise</h3>
                <p className="text-xs text-[var(--sd-text-muted)] mt-1.5 leading-relaxed">
                  Strict separation of duties, Tier 3 dual-MFA sign-off, HSM keys, and air-gapped support for regulated infrastructure.
                </p>
              </div>

              <div className="py-2 border-y border-[var(--sd-border)]">
                <div className="flex items-baseline gap-1">
                  <span className="text-3xl font-light font-mono text-[var(--sd-text)]">
                    {currencySymbol}
                    {billingInterval === "year"
                      ? Math.round(1599 * currencyMultiplier)
                      : Math.round(1999 * currencyMultiplier)}
                  </span>
                  <span className="text-xs text-[var(--sd-text-muted)]">
                    / mo {billingInterval === "year" ? "(billed annually)" : ""}
                  </span>
                </div>
                <p className="text-[11px] text-[var(--sd-gold)] mt-0.5">Up to 10,000 endpoints &amp; custom quotas</p>
              </div>

              <ul className="space-y-2.5 text-xs text-[var(--sd-text-muted)]">
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-gold)] shrink-0" />
                  <span className="text-[var(--sd-text)] font-medium">10,000+ Endpoint Capacity</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-gold)] shrink-0" />
                  <span>Strict Separation of Duties &amp; Tier 3 Dual MFA</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-gold)] shrink-0" />
                  <span>Air-Gapped &amp; AWS GovCloud Support</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-gold)] shrink-0" />
                  <span>Hardware Security Module (HSM) PKI Keys</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-gold)] shrink-0" />
                  <span>SOC 2 Type II &amp; Merkle Audit Vault</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-[var(--sd-gold)] shrink-0" />
                  <span>Dedicated SOC 1h Response SLA</span>
                </li>
              </ul>
            </div>

            <button
              onClick={() => handleLaunchCheckout("enterprise")}
              disabled={isLoadingCheckout === "enterprise"}
              className="mt-6 w-full py-2.5 rounded-full border border-[var(--sd-border)] sd-surface text-xs font-medium text-[var(--sd-text)] hover:bg-[var(--sd-panel-raised)] transition-colors cursor-pointer flex items-center justify-center gap-2"
            >
              {isLoadingCheckout === "enterprise" ? (
                <span>Launching Stripe Checkout...</span>
              ) : (
                <>
                  <span>Select Enterprise</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Feature Comparison Matrix */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-8 shadow-xs">
          <div className="mb-6">
            <h2 className="text-xl font-light text-[var(--sd-text)]">Detailed Feature Matrix</h2>
            <p className="text-xs text-[var(--sd-text-muted)] mt-1">
              Verify capabilities across telemetry, governance, fleet dispatch, and regulatory compliance.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--sd-border)] text-[var(--sd-text-muted)] font-mono uppercase">
                  <th className="py-3 px-4">Feature / Capability</th>
                  <th className="py-3 px-4">Community Pilot</th>
                  <th className="py-3 px-4 text-[var(--sd-pine)]">Professional</th>
                  <th className="py-3 px-4 text-[var(--sd-gold)]">Enterprise</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--sd-border)]">
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">Endpoint Agent Capacity</td>
                  <td className="py-3 px-4">Up to 5</td>
                  <td className="py-3 px-4">Up to 100</td>
                  <td className="py-3 px-4">Up to 10,000</td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">Evidence &amp; Telemetry Retention</td>
                  <td className="py-3 px-4">7 days</td>
                  <td className="py-3 px-4">90 days</td>
                  <td className="py-3 px-4">365 days</td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">Pre-Flight LVM Snapshots &amp; Rollback</td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">AI Blast Radius &amp; Kill-Chain Modeling</td>
                  <td className="py-3 px-4"><X className="w-4 h-4 text-[var(--sd-text-dim)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">Tier 1 Automated Remediation</td>
                  <td className="py-3 px-4"><X className="w-4 h-4 text-[var(--sd-text-dim)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">Tier 3 Dual SuperAdmin Sign-Off (SoD)</td>
                  <td className="py-3 px-4"><X className="w-4 h-4 text-[var(--sd-text-dim)]" /></td>
                  <td className="py-3 px-4"><X className="w-4 h-4 text-[var(--sd-text-dim)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-[var(--sd-text)]">Air-Gapped &amp; Offline Token Signing</td>
                  <td className="py-3 px-4"><X className="w-4 h-4 text-[var(--sd-text-dim)]" /></td>
                  <td className="py-3 px-4"><X className="w-4 h-4 text-[var(--sd-text-dim)]" /></td>
                  <td className="py-3 px-4"><Check className="w-4 h-4 text-[var(--sd-pine)]" /></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}
