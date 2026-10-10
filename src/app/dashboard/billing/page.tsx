"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  CreditCard,
  Shield,
  Key,
  Server,
  Download,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
  Plus,
  ArrowUpRight,
  FileText,
  Clock,
  Laptop,
  Check,
  X,
  Copy,
  Terminal,
} from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";

interface SubscriptionDetails {
  tier: "community" | "professional" | "enterprise";
  name: string;
  status: "active" | "trialing" | "past_due" | "grace_period" | "suspended" | "cancelled" | "expired";
  currentPeriodEnd: string;
  enrolledEndpoints: number;
  maxEndpoints: number;
  maxUsers: number;
  retentionDays: number;
  subscriptionId?: string;
  paymentProvider?: string;
}

interface InvoiceRecord {
  id: string;
  invoiceNumber: string | null;
  amountPaid: number;
  amountDue: number;
  currency: string;
  status: string;
  periodEnd: string | null;
  hostedInvoiceUrl: string | null;
  invoicePdfUrl: string | null;
  paidAt: string | null;
  createdAt: string;
}

interface ActivationRecord {
  installationId: string;
  deviceIdentity: string;
  certificateFingerprint: string;
  platform?: string;
  productVersion?: string;
  state: string;
  activatedAt: string;
  lastHeartbeatAt?: string;
}

export default function CustomerBillingPage() {
  const { activeUser } = useChat();
  const [subscription, setSubscription] = useState<SubscriptionDetails | null>(null);
  const [invoices, setInvoices] = useState<InvoiceRecord[]>([]);
  const [activations, setActivations] = useState<ActivationRecord[]>([]);
  const [offlineToken, setOfflineToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Modals
  const [showChangePlanModal, setShowChangePlanModal] = useState(false);
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [showActivateKeyModal, setShowActivateKeyModal] = useState(false);
  const [licenseKeyInput, setLicenseKeyInput] = useState("");
  const [targetTier, setTargetTier] = useState<"professional" | "enterprise">("professional");
  const [copiedToken, setCopiedToken] = useState(false);

  const fetchBillingData = async () => {
    setIsLoading(true);
    try {
      // 1. Fetch Subscription
      const subRes = await fetch("/api/v1/billing/subscription");
      if (subRes.ok) {
        const subData = await subRes.json();
        setSubscription(subData.subscription);
      }

      // 2. Fetch Invoices
      const invRes = await fetch("/api/v1/billing/invoices");
      if (invRes.ok) {
        const invData = await invRes.json();
        setInvoices(invData.invoices || []);
      }

      // 3. Fetch Activations
      const actRes = await fetch("/api/v1/licenses/activations");
      if (actRes.ok) {
        const actData = await actRes.json();
        setActivations(actData.activations || []);
      }
    } catch (err) {
      console.error("Failed to load billing data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchBillingData();
  }, [activeUser.tenantId]);

  const handleOpenStripePortal = async () => {
    setIsActionLoading(true);
    try {
      const res = await fetch("/api/v1/billing/portal-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ returnUrl: window.location.href }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to launch portal");
      if (data.portalUrl) window.location.href = data.portalUrl;
    } catch (err: unknown) {
      setNotification({
        type: "error",
        text: err instanceof Error ? err.message : "Portal redirect failed",
      });
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleChangePlan = async () => {
    setIsActionLoading(true);
    try {
      const res = await fetch("/api/v1/billing/change-plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetTier }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Plan change failed");
      setNotification({ type: "success", text: data.message });
      setShowChangePlanModal(false);
      fetchBillingData();
    } catch (err: unknown) {
      setNotification({ type: "error", text: err instanceof Error ? err.message : "Plan change failed" });
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleCancelSubscription = async (immediate: boolean) => {
    setIsActionLoading(true);
    try {
      const res = await fetch("/api/v1/billing/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ immediate }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Cancellation failed");
      setNotification({ type: "success", text: data.message });
      setShowCancelModal(false);
      fetchBillingData();
    } catch (err: unknown) {
      setNotification({ type: "error", text: err instanceof Error ? err.message : "Cancellation failed" });
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleActivateLicenseKey = async () => {
    if (!licenseKeyInput.trim()) return;
    setIsActionLoading(true);
    try {
      const res = await fetch("/api/v1/billing/licenses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ licenseKey: licenseKeyInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "License activation failed");
      setNotification({ type: "success", text: data.message });
      setShowActivateKeyModal(false);
      setLicenseKeyInput("");
      fetchBillingData();
    } catch (err: unknown) {
      setNotification({ type: "error", text: err instanceof Error ? err.message : "Activation failed" });
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleGenerateOfflineToken = async () => {
    try {
      const res = await fetch("/api/v1/billing/licenses?offline=true");
      if (res.ok) {
        const data = await res.json();
        if (data.offlineCache) {
          setOfflineToken(data.offlineCache);
          setNotification({ type: "success", text: "Signed offline entitlement cache token generated." });
        }
      }
    } catch {
      setNotification({ type: "error", text: "Failed to generate offline token." });
    }
  };

  const handleDeactivateInstallation = async (installationId: string) => {
    if (!confirm(`Are you sure you want to deactivate installation '${installationId}'?`)) return;
    try {
      const res = await fetch(`/api/v1/licenses/activations/${installationId}/deactivate`, {
        method: "POST",
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Deactivation failed");
      setNotification({ type: "success", text: data.message });
      fetchBillingData();
    } catch (err: unknown) {
      setNotification({ type: "error", text: err instanceof Error ? err.message : "Deactivation failed" });
    }
  };

  const quotaPercent = subscription
    ? Math.round((subscription.enrolledEndpoints / subscription.maxEndpoints) * 100)
    : 0;

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="max-w-7xl mx-auto px-6 py-8 flex-1 w-full space-y-8">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[var(--sd-border)] pb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono uppercase tracking-widest text-[var(--sd-pine)] font-semibold">
                Commercial Portal
              </span>
              <span className="text-xs text-[var(--sd-text-muted)]">•</span>
              <span className="text-xs text-[var(--sd-text-muted)] font-mono">{activeUser.tenantName}</span>
            </div>
            <h1 className="text-3xl font-light text-[var(--sd-text)] tracking-tight">
              Subscription &amp; License Management
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/pricing"
              className="px-4 py-2 rounded-full border border-[var(--sd-border)] sd-surface text-xs font-medium text-[var(--sd-text)] hover:bg-[var(--sd-panel-raised)] transition-colors inline-flex items-center gap-1.5"
            >
              <span>Compare Plans</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
            <button
              onClick={handleOpenStripePortal}
              disabled={isActionLoading}
              className="px-4 py-2 rounded-full bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[var(--sd-on-accent)] text-xs font-medium shadow-xs transition-colors inline-flex items-center gap-2 cursor-pointer"
            >
              <CreditCard className="w-3.5 h-3.5" />
              <span>Stripe Customer Portal</span>
            </button>
          </div>
        </div>

        {notification && (
          <div
            className={`p-4 rounded-xl text-xs flex items-center justify-between ${
              notification.type === "success"
                ? "bg-[var(--sd-success-dim)] border border-[var(--sd-success-border)] text-[var(--sd-success)]"
                : "bg-[var(--sd-danger-dim)] border border-[var(--sd-danger-border)] text-[var(--sd-danger)]"
            }`}
          >
            <span>{notification.text}</span>
            <button onClick={() => setNotification(null)} className="cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Overview Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Subscription Card */}
          <div className="md:col-span-2 rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-[var(--sd-pine)]/10 border border-[var(--sd-pine)]/20 flex items-center justify-center">
                    <Shield className="w-4.5 h-4.5 text-[var(--sd-pine)]" />
                  </div>
                  <div>
                    <h3 className="text-base font-medium text-[var(--sd-text)]">
                      {subscription?.name || "Loading plan..."}
                    </h3>
                    <p className="text-[11px] text-[var(--sd-text-muted)] font-mono capitalize">
                      Provider: {subscription?.paymentProvider || "Stripe"}
                    </p>
                  </div>
                </div>

                <span
                  className={`px-2.5 py-1 rounded-full text-xs font-mono uppercase font-semibold tracking-wider ${
                    subscription?.status === "active"
                      ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]"
                      : subscription?.status === "past_due" || subscription?.status === "grace_period"
                      ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                      : "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]"
                  }`}
                >
                  {subscription?.status || "active"}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 py-4 border-y border-[var(--sd-border)]">
                <div>
                  <span className="text-[11px] text-[var(--sd-text-muted)] uppercase font-mono">Current Tier</span>
                  <p className="text-sm font-semibold capitalize text-[var(--sd-text)] mt-0.5">
                    {subscription?.tier || "Community"}
                  </p>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--sd-text-muted)] uppercase font-mono">Period End</span>
                  <p className="text-xs font-medium text-[var(--sd-text)] mt-1">
                    {subscription?.currentPeriodEnd
                      ? new Date(subscription.currentPeriodEnd).toLocaleDateString()
                      : "—"}
                  </p>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--sd-text-muted)] uppercase font-mono">Retention</span>
                  <p className="text-sm font-semibold text-[var(--sd-text)] mt-0.5">
                    {subscription?.retentionDays || 7} Days
                  </p>
                </div>
                <div>
                  <span className="text-[11px] text-[var(--sd-text-muted)] uppercase font-mono">User Cap</span>
                  <p className="text-sm font-semibold text-[var(--sd-text)] mt-0.5">
                    {subscription?.maxUsers || 10} Users
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 flex flex-wrap items-center gap-3">
              <button
                onClick={() => setShowChangePlanModal(true)}
                className="px-4 py-2 rounded-xl bg-[var(--sd-pine)] text-[var(--sd-on-accent)] text-xs font-semibold hover:bg-[var(--sd-pine-dark)] transition-colors cursor-pointer"
              >
                Change Plan / Upgrade
              </button>
              <button
                onClick={() => setShowCancelModal(true)}
                className="px-4 py-2 rounded-xl border border-[var(--sd-border)] sd-surface text-xs font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-danger)] transition-colors cursor-pointer"
              >
                Cancel Subscription
              </button>
              <button
                onClick={() => setShowActivateKeyModal(true)}
                className="px-4 py-2 rounded-xl border border-[var(--sd-border)] sd-surface text-xs font-medium text-[var(--sd-text)] hover:bg-[var(--sd-panel-raised)] transition-colors cursor-pointer ml-auto flex items-center gap-1.5"
              >
                <Key className="w-3.5 h-3.5" />
                <span>Activate License Key</span>
              </button>
            </div>
          </div>

          {/* Quotas & Capacity Card */}
          <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono uppercase tracking-wider text-[var(--sd-text-muted)]">
                  Endpoint Quota
                </span>
                <Server className="w-4 h-4 text-[var(--sd-pine)]" />
              </div>

              <div className="flex items-baseline gap-2 mb-2">
                <span className="text-3xl font-light font-mono text-[var(--sd-text)]">
                  {subscription?.enrolledEndpoints || 0}
                </span>
                <span className="text-sm text-[var(--sd-text-muted)]">
                  / {subscription?.maxEndpoints || 5} seats
                </span>
              </div>

              {/* Progress bar */}
              <div className="w-full h-2 rounded-full bg-[var(--sd-panel-raised)] overflow-hidden my-3">
                <div
                  className={`h-full transition-all ${
                    quotaPercent >= 110
                      ? "bg-[var(--sd-danger)]"
                      : quotaPercent >= 100
                      ? "bg-[var(--sd-warning)]"
                      : "bg-[var(--sd-pine)]"
                  }`}
                  style={{ width: `${Math.min(quotaPercent, 100)}%` }}
                />
              </div>

              <p className="text-[11px] text-[var(--sd-text-muted)] leading-relaxed">
                {quotaPercent >= 110 ? (
                  <span className="text-[var(--sd-danger)] font-medium">
                    Hard enrollment block at 110%+. Existing agents and telemetry ingestion remain protected.
                  </span>
                ) : quotaPercent >= 100 ? (
                  <span className="text-[var(--sd-warning)] font-medium">
                    Plan capacity reached. Tenant is in 14-day grace period. Upgrade recommended.
                  </span>
                ) : (
                  <span>Usage is normal. Soft warning threshold triggers at 90%.</span>
                )}
              </p>
            </div>

            <div className="pt-4 border-t border-[var(--sd-border)] mt-4">
              <button
                onClick={handleGenerateOfflineToken}
                className="w-full py-2 rounded-lg border border-[var(--sd-border)] text-[11px] font-mono text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-raised)] transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Offline Entitlement Cache</span>
              </button>
            </div>
          </div>
        </div>

        {offlineToken && (
          <div className="p-4 rounded-xl border border-[var(--sd-pine)]/40 bg-[var(--sd-surface)] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-medium text-[var(--sd-pine)]">
                Signed Offline Entitlement Cache Token (Air-Gapped / Disconnected SOC)
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(offlineToken);
                  setCopiedToken(true);
                  setTimeout(() => setCopiedToken(false), 2000);
                }}
                className="px-2 py-1 rounded text-xs bg-[var(--sd-panel-raised)] text-[var(--sd-text)] flex items-center gap-1 cursor-pointer"
              >
                {copiedToken ? <Check className="w-3.5 h-3.5 text-[var(--sd-success)]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedToken ? "Copied" : "Copy Token"}</span>
              </button>
            </div>
            <textarea
              readOnly
              value={offlineToken}
              className="w-full h-20 p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] font-mono text-[11px] text-[var(--sd-text-muted)] focus:outline-none"
            />
          </div>
        )}

        {/* License Activations Table */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-medium text-[var(--sd-text)]">Active Installations &amp; Seats</h2>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Verified endpoint installations bound by mTLS X.509 certificates and cryptographic proof.
              </p>
            </div>
            <span className="text-xs font-mono text-[var(--sd-pine)]">
              {activations.length} Active Node{activations.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--sd-border)] text-[var(--sd-text-muted)] font-mono uppercase">
                  <th className="py-2.5 px-3">Installation ID</th>
                  <th className="py-2.5 px-3">Device Identity</th>
                  <th className="py-2.5 px-3">Cert Fingerprint</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Activated At</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--sd-border)] font-mono">
                {activations.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-xs text-[var(--sd-text-muted)]">
                      No endpoint installations currently active. Enroll your first agent via the commands below.
                    </td>
                  </tr>
                ) : (
                  activations.map((act) => (
                    <tr key={act.installationId} className="hover:bg-[var(--sd-panel-raised)] transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-[var(--sd-text)]">{act.installationId}</td>
                      <td className="py-2.5 px-3 text-[var(--sd-text-muted)]">{act.deviceIdentity}</td>
                      <td className="py-2.5 px-3 text-[var(--sd-text-dim)]">
                        {act.certificateFingerprint.substring(0, 16)}...
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            act.state === "ACTIVE"
                              ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)]"
                              : "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)]"
                          }`}
                        >
                          {act.state}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-[var(--sd-text-muted)]">
                        {new Date(act.activatedAt).toLocaleDateString()}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => handleDeactivateInstallation(act.installationId)}
                          className="px-2.5 py-1 rounded bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] hover:bg-[var(--sd-danger)] hover:text-white transition-colors cursor-pointer text-[11px]"
                        >
                          Deactivate
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Invoices Table */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-medium text-[var(--sd-text)]">Invoices &amp; Receipts</h2>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Authoritative payment records and downloadable PDF invoices from Stripe.
              </p>
            </div>
            <button
              onClick={handleOpenStripePortal}
              className="text-xs text-[var(--sd-pine)] hover:underline inline-flex items-center gap-1"
            >
              <span>View in Stripe Portal</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--sd-border)] text-[var(--sd-text-muted)] font-mono uppercase">
                  <th className="py-2.5 px-3">Invoice Number</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3">Amount</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Receipt / PDF</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--sd-border)]">
                {invoices.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-xs text-[var(--sd-text-muted)]">
                      No invoices recorded yet. Invoices appear automatically upon Stripe payment processing.
                    </td>
                  </tr>
                ) : (
                  invoices.map((inv) => (
                    <tr key={inv.id} className="hover:bg-[var(--sd-panel-raised)] transition-colors">
                      <td className="py-2.5 px-3 font-mono font-medium text-[var(--sd-text)]">
                        {inv.invoiceNumber || inv.id}
                      </td>
                      <td className="py-2.5 px-3 text-[var(--sd-text-muted)]">
                        {new Date(inv.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-2.5 px-3 font-mono font-semibold text-[var(--sd-text)]">
                        ${inv.amountPaid.toFixed(2)} {inv.currency}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                            inv.status === "paid"
                              ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)]"
                              : "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)]"
                          }`}
                        >
                          {inv.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {inv.hostedInvoiceUrl ? (
                          <a
                            href={inv.hostedInvoiceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-[var(--sd-pine)] hover:underline inline-flex items-center gap-1"
                          >
                            <span>Receipt</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        ) : (
                          <span className="text-[var(--sd-text-dim)]">—</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Private Package & Installation Instructions */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-xs space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[var(--sd-pine)]/10 border border-[var(--sd-pine)]/20 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-[var(--sd-pine)]" />
            </div>
            <div>
              <h2 className="text-base font-medium text-[var(--sd-text)]">Private Endpoint Installation Commands</h2>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Install authorized universal Go daemons with automatic mTLS enrollment for tenant {activeUser.tenantId}.
              </p>
            </div>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <span className="text-xs font-mono text-[var(--sd-text-muted)] block mb-1">
                Linux / Ubuntu / RHEL (systemd):
              </span>
              <pre className="p-3 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs font-mono text-[var(--sd-wheat)] overflow-x-auto">
                curl -sSL https://control.shielddesk.io/install.sh | sudo bash -s -- --control-plane &quot;https://control.shielddesk.io&quot; --tenant &quot;{activeUser.tenantId}&quot;
              </pre>
            </div>

            <div>
              <span className="text-xs font-mono text-[var(--sd-text-muted)] block mb-1">
                Windows (PowerShell 7+ as Administrator):
              </span>
              <pre className="p-3 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs font-mono text-[var(--sd-wheat)] overflow-x-auto">
                powershell -ExecutionPolicy Bypass -Command &quot;Invoke-WebRequest -Uri &apos;https://control.shielddesk.io/install-windows.ps1&apos; -OutFile &apos;install.ps1&apos;; .\install.ps1 -ControlPlane &apos;https://control.shielddesk.io&apos; -TenantId &apos;{activeUser.tenantId}&apos;&quot;
              </pre>
            </div>
          </div>
        </div>

        {/* Modals */}
        {showChangePlanModal && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="max-w-md w-full rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-2xl space-y-4">
              <h3 className="text-lg font-medium text-[var(--sd-text)]">Change Subscription Plan</h3>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Upgrades take effect immediately with Stripe proration. Downgrades take effect at the end of the billing cycle.
              </p>

              <div className="space-y-2 py-2">
                {(["professional", "enterprise"] as const).map((t) => (
                  <label
                    key={t}
                    className={`flex items-center justify-between p-3 rounded-xl border cursor-pointer transition-colors ${
                      targetTier === t
                        ? "border-[var(--sd-pine)] bg-[var(--sd-pine)]/10"
                        : "border-[var(--sd-border)] hover:bg-[var(--sd-panel-raised)]"
                    }`}
                  >
                    <div>
                      <p className="text-xs font-semibold capitalize text-[var(--sd-text)]">{t}</p>
                      <p className="text-[11px] text-[var(--sd-text-muted)]">
                        {t === "professional" ? "100 Endpoints, AI blast radius" : "10,000 Endpoints, HSM PKI keys"}
                      </p>
                    </div>
                    <input
                      type="radio"
                      name="tierSelect"
                      value={t}
                      checked={targetTier === t}
                      onChange={() => setTargetTier(t)}
                    />
                  </label>
                ))}
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  onClick={() => setShowChangePlanModal(false)}
                  className="px-4 py-2 rounded-xl text-xs text-[var(--sd-text-muted)] hover:bg-[var(--sd-panel-raised)] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleChangePlan}
                  disabled={isActionLoading}
                  className="px-4 py-2 rounded-xl bg-[var(--sd-pine)] text-[var(--sd-on-accent)] text-xs font-medium cursor-pointer"
                >
                  {isActionLoading ? "Updating..." : "Confirm Change"}
                </button>
              </div>
            </div>
          </div>
        )}

        {showCancelModal && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="max-w-md w-full rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-2xl space-y-4">
              <div className="flex items-center gap-3 text-[var(--sd-danger)]">
                <AlertTriangle className="w-6 h-6" />
                <h3 className="text-lg font-medium text-[var(--sd-text)]">Cancel Subscription</h3>
              </div>
              <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
                By default, paid access remains active until the end of your billing period ({subscription?.currentPeriodEnd ? new Date(subscription.currentPeriodEnd).toLocaleDateString() : "next cycle"}).
                No customer evidence will be deleted.
              </p>

              <div className="flex justify-end gap-2 pt-4">
                <button
                  onClick={() => setShowCancelModal(false)}
                  className="px-4 py-2 rounded-xl text-xs text-[var(--sd-text-muted)] hover:bg-[var(--sd-panel-raised)] cursor-pointer"
                >
                  Keep Subscription
                </button>
                <button
                  onClick={() => handleCancelSubscription(false)}
                  disabled={isActionLoading}
                  className="px-4 py-2 rounded-xl bg-[var(--sd-danger)] text-white text-xs font-medium cursor-pointer"
                >
                  {isActionLoading ? "Cancelling..." : "Cancel at Period End"}
                </button>
              </div>
            </div>
          </div>
        )}

        {showActivateKeyModal && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="max-w-md w-full rounded-2xl border border-[var(--sd-border)] sd-surface p-6 shadow-2xl space-y-4">
              <h3 className="text-lg font-medium text-[var(--sd-text)]">Activate Commercial License</h3>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Enter your cryptographically signed license key to activate entitlements for tenant {activeUser.tenantId}.
              </p>

              <textarea
                value={licenseKeyInput}
                onChange={(e) => setLicenseKeyInput(e.target.value)}
                placeholder="Paste license key (e.g. eyJsaWNlbnNlSWQi...)"
                rows={3}
                className="w-full p-3 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs font-mono text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)]"
              />

              <div className="flex justify-end gap-2 pt-2">
                <button
                  onClick={() => setShowActivateKeyModal(false)}
                  className="px-4 py-2 rounded-xl text-xs text-[var(--sd-text-muted)] hover:bg-[var(--sd-panel-raised)] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleActivateLicenseKey}
                  disabled={isActionLoading || !licenseKeyInput.trim()}
                  className="px-4 py-2 rounded-xl bg-[var(--sd-pine)] text-[var(--sd-on-accent)] text-xs font-medium cursor-pointer"
                >
                  {isActionLoading ? "Activating..." : "Activate License"}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
