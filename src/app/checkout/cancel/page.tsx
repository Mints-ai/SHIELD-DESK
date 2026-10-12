"use client";

import React from "react";
import Link from "next/link";
import { AlertCircle, ArrowLeft, Shield } from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";

export default function CheckoutCancelPage() {
  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />
      <main className="max-w-xl mx-auto px-6 py-20 flex-1 flex flex-col items-center justify-center text-center">
        <div className="w-full rounded-2xl border border-[var(--sd-border)] sd-surface p-8 shadow-xl space-y-6">
          <div className="w-14 h-14 rounded-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] flex items-center justify-center mx-auto text-[var(--sd-text-muted)]">
            <AlertCircle className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-light text-[var(--sd-text)]">Checkout Cancelled</h1>
          <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed max-w-sm mx-auto">
            Your Stripe Checkout session was cancelled and no charge was processed. Your existing subscription and quotas remain unchanged.
          </p>
          <div className="pt-4 flex justify-center gap-3">
            <Link
              href="/pricing"
              className="px-5 py-2.5 rounded-full bg-[var(--sd-pine)] text-[var(--sd-on-accent)] text-xs font-semibold shadow-xs transition-colors inline-flex items-center gap-2"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Return to Pricing Plans</span>
            </Link>
            <Link
              href="/dashboard/billing"
              className="px-5 py-2.5 rounded-full border border-[var(--sd-border)] sd-surface text-[var(--sd-text)] text-xs font-medium hover:bg-[var(--sd-panel-raised)] transition-colors inline-flex items-center"
            >
              Customer Billing
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
