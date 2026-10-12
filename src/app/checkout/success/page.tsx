"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, RefreshCw, AlertCircle, ArrowRight, Shield, Lock } from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";

export default function CheckoutSuccessPage() {
  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />
      <main className="max-w-xl mx-auto px-6 py-20 flex-1 flex flex-col items-center justify-center text-center">
        <React.Suspense fallback={<RefreshCw className="w-8 h-8 animate-spin text-[var(--sd-pine)]" />}>
          <CheckoutStatusVerifier />
        </React.Suspense>
      </main>
    </div>
  );
}

function CheckoutStatusVerifier() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("session_id");
  const attemptId = searchParams.get("attempt_id");

  const [status, setStatus] = useState<"verifying" | "provisioned" | "pending_webhook" | "failed">("verifying");
  const [tier, setTier] = useState<string>("professional");
  const [pollCount, setPollCount] = useState(0);

  useEffect(() => {
    let isMounted = true;
    let timer: NodeJS.Timeout;

    const checkStatus = async () => {
      try {
        const queryParams = new URLSearchParams();
        if (attemptId) queryParams.set("attemptId", attemptId);
        if (sessionId) queryParams.set("sessionId", sessionId);

        const res = await fetch(`/api/v1/billing/checkout-status?${queryParams.toString()}`);
        if (res.ok) {
          const data = await res.json();
          if (data.isProvisioned) {
            if (isMounted) {
              setTier(data.currentSubscription?.tier || data.planId || "professional");
              setStatus("provisioned");
            }
            return;
          }
        }
      } catch {
        // Retry
      }

      setPollCount((prev) => {
        const next = prev + 1;
        if (next > 12) {
          if (isMounted) setStatus("pending_webhook");
        } else {
          timer = setTimeout(checkStatus, 3000);
        }
        return next;
      });
    };

    checkStatus();

    return () => {
      isMounted = false;
      if (timer) clearTimeout(timer);
    };
  }, [attemptId, sessionId]);

  return (
    <div className="w-full rounded-2xl border border-[var(--sd-border)] sd-surface p-8 shadow-xl space-y-6">
      {status === "verifying" && (
        <div className="space-y-4">
          <div className="w-14 h-14 rounded-full bg-[var(--sd-pine)]/10 border border-[var(--sd-pine)]/20 flex items-center justify-center mx-auto">
            <RefreshCw className="w-7 h-7 text-[var(--sd-pine)] animate-spin" />
          </div>
          <h1 className="text-2xl font-light text-[var(--sd-text)]">Verifying Subscription Provisioning</h1>
          <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed max-w-sm mx-auto">
            Payment received by Stripe. Confirming cryptographic webhook signature and writing durable ledger entry...
          </p>
          <div className="font-mono text-[11px] text-[var(--sd-pine)] bg-[var(--sd-pine)]/10 py-1.5 px-3 rounded-lg w-fit mx-auto">
            Polling settlement ledger ({pollCount}/12)
          </div>
        </div>
      )}

      {status === "provisioned" && (
        <div className="space-y-4">
          <div className="w-14 h-14 rounded-full bg-[var(--sd-success-dim)] border border-[var(--sd-success-border)] flex items-center justify-center mx-auto">
            <CheckCircle2 className="w-7 h-7 text-[var(--sd-success)]" />
          </div>
          <h1 className="text-2xl font-light text-[var(--sd-text)]">Subscription Verified &amp; Active</h1>
          <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed max-w-sm mx-auto">
            Your ShieldDesk subscription has been successfully provisioned on tier{" "}
            <strong className="text-[var(--sd-wheat)] capitalize">{tier}</strong>. Entitlements are now live.
          </p>
          <div className="pt-4 flex flex-col sm:flex-row gap-3 justify-center">
            <Link
              href="/dashboard/billing"
              className="px-5 py-2.5 rounded-full bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[var(--sd-on-accent)] text-xs font-semibold shadow-xs transition-colors inline-flex items-center justify-center gap-2"
            >
              <span>Manage Billing &amp; Licenses</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
            <Link
              href="/"
              className="px-5 py-2.5 rounded-full border border-[var(--sd-border)] sd-surface text-[var(--sd-text)] text-xs font-medium hover:bg-[var(--sd-panel-raised)] transition-colors inline-flex items-center justify-center"
            >
              Incident Workspace
            </Link>
          </div>
        </div>
      )}

      {status === "pending_webhook" && (
        <div className="space-y-4">
          <div className="w-14 h-14 rounded-full bg-[var(--sd-warning-dim)] border border-[var(--sd-warning-border)] flex items-center justify-center mx-auto">
            <Shield className="w-7 h-7 text-[var(--sd-warning)]" />
          </div>
          <h1 className="text-2xl font-light text-[var(--sd-text)]">Payment Received by Stripe</h1>
          <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed max-w-sm mx-auto">
            Stripe confirmed payment settlement. Background webhook reconciliation is queued. Your dashboard will reflect the updated tier shortly.
          </p>
          <div className="pt-4">
            <Link
              href="/dashboard/billing"
              className="px-5 py-2.5 rounded-full bg-[var(--sd-pine)] text-[var(--sd-on-accent)] text-xs font-medium inline-flex items-center gap-2"
            >
              <span>Go to Customer Billing</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
