"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Lock,
  Building2,
  Mail,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

function getSafeRedirect(target: string | null, fallback = "/"): string {
  if (!target) return fallback;
  // Strictly prevent open redirects to external protocols or scheme-relative URLs
  if (target.startsWith("/") && !target.startsWith("//") && !target.startsWith("/\\")) {
    return target;
  }
  return fallback;
}

function SignupForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const rawRedirect = searchParams.get("redirect");
  const redirectTarget = getSafeRedirect(rawRedirect, "/");
  const planParam = searchParams.get("plan");
  const intervalParam = searchParams.get("interval") || "month";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [agreedToTerms, setAgreedToTerms] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [clientIp, setClientIp] = useState<string>("");

  useEffect(() => {
    fetch("https://api.ipify.org?format=json")
      .then((res) => res.json())
      .then((data) => {
        if (data?.ip) setClientIp(data.ip);
      })
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreedToTerms) {
      setErrorMessage("You must accept the Autonomous Security & DPA Terms.");
      return;
    }

    if (password.length < 8) {
      setErrorMessage("Password must be at least 8 characters long.");
      return;
    }

    setLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    const authHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      ...(clientIp ? { "x-client-ip": clientIp } : {}),
    };

    try {
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          email,
          password,
          organizationName: orgName,
          clientIp,
        }),
      });

      const data = await res.json();
      if (res.ok) {
        setSuccessMessage("Organization registered successfully. Preparing your workspace...");
        const target = planParam
          ? `/pricing?plan=${encodeURIComponent(planParam)}&interval=${encodeURIComponent(intervalParam)}`
          : redirectTarget;
        setTimeout(() => router.push(target), 800);
      } else {
        setErrorMessage(data.error || "Registration failed. Please try again.");
      }
    } catch {
      setErrorMessage("Network error connecting to ShieldDesk authentication gateway.");
    } finally {
      setLoading(false);
    }
  };

  const planDisplayName =
    planParam === "professional"
      ? "ShieldDesk SOC Pro"
      : planParam === "community"
        ? "ShieldDesk Community Pilot"
        : planParam === "enterprise"
          ? "ShieldDesk Autonomous Enterprise"
          : planParam;

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col justify-center items-center p-4 font-sans selection:bg-[var(--sd-pine)] selection:text-[var(--sd-on-accent)] relative">
      <div className="fixed inset-0 pointer-events-none sd-ambient-glow" />

      <div className="relative w-full max-w-md flex flex-col gap-6 z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center gap-3">
          <div className="h-16 w-16 rounded-2xl sd-surface border border-[var(--sd-border)] p-1.5 flex items-center justify-center shadow-lg shadow-[var(--sd-pine)]/15 overflow-hidden">
            <img src="/logo.png" alt="ShieldDesk" className="h-full w-full object-contain" />
          </div>
          <div>
            <div className="flex items-center justify-center gap-2">
              <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                Shield<span className="text-[var(--sd-wheat)]">Desk</span>
                <span className="text-[11px] text-[var(--sd-wheat)] align-super">™</span>
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-medium sd-surface text-[var(--sd-pine)] border border-[var(--sd-border)] uppercase tracking-wider font-mono shadow-xs">
                SOC v2.5
              </span>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
              Create your organization and deploy autonomous security operations.
            </p>
          </div>
        </div>

        {/* Selected Plan Banner if arriving from website CTA */}
        {planParam && (
          <div className="p-3.5 rounded-xl border border-[var(--sd-pine)]/30 bg-[var(--sd-panel-raised)] shadow-xs flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-[var(--sd-pine)]/10 text-[var(--sd-pine)]">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <div className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-pine)] font-semibold">
                  Selected Subscription Intent
                </div>
                <div className="text-sm font-medium text-[var(--sd-text)] capitalize">
                  {planDisplayName}
                  <span className="text-xs text-[var(--sd-text-muted)] ml-1.5 font-normal">
                    ({intervalParam === "year" ? "Annual Billing" : "Monthly Billing"})
                  </span>
                </div>
              </div>
            </div>
            <Link
              href="/pricing"
              className="text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition underline underline-offset-2 shrink-0"
            >
              Change
            </Link>
          </div>
        )}

        {/* Signup Card */}
        <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xl flex flex-col gap-5">
          <div className="border-b border-[var(--sd-border)] pb-3">
            <h2 className="text-sm font-medium text-[var(--sd-text)]">
              Register Organization Account
            </h2>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-0.5">
              Your account will be provisioned as the tenant organization owner and billing administrator.
            </p>
          </div>

          {errorMessage && (
            <div className="p-3 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] text-[13px] flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--sd-danger)]" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="p-3 rounded-xl border border-[var(--sd-pine)]/30 bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] text-[13px] flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--sd-pine)]" />
              <span>{successMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                <Building2 className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                <span>Organization Name</span>
              </label>
              <input
                type="text"
                required
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="e.g. Mints Global Cybersecurity"
                className="w-full px-3 py-2 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-sm text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)]/50 focus:outline-none focus:border-[var(--sd-pine)] transition"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                <Mail className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                <span>Corporate Work Email</span>
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="soc-lead@company.com"
                className="w-full px-3 py-2 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-sm text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)]/50 focus:outline-none focus:border-[var(--sd-pine)] transition font-mono text-[13px]"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                <KeyRound className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                <span>Master Password</span>
              </label>
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 8 characters"
                className="w-full px-3 py-2 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-sm text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)]/50 focus:outline-none focus:border-[var(--sd-pine)] transition"
              />
              <span className="text-[10px] text-[var(--sd-text-muted)]">
                Stored as a salted Argon2/Scrypt hash.
              </span>
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer pt-1 text-[12px] text-[var(--sd-text-muted)] leading-relaxed select-none">
              <input
                type="checkbox"
                checked={agreedToTerms}
                onChange={(e) => setAgreedToTerms(e.target.checked)}
                className="mt-1 rounded border-[var(--sd-border)] text-[var(--sd-pine)] focus:ring-0 focus:ring-offset-0 cursor-pointer"
              />
              <span>
                I agree to the{" "}
                <span className="text-[var(--sd-text)] underline underline-offset-2">
                  Autonomous Security Governance Policy
                </span>
                , SOC terms, and Data Processing Agreement.
              </span>
            </label>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 rounded-xl bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-medium text-sm hover:opacity-95 active:opacity-90 transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2 shadow-sm shadow-[var(--sd-pine)]/20"
            >
              {loading ? (
                <>
                  <div className="h-4 w-4 border-2 border-[var(--sd-on-accent)]/30 border-t-[var(--sd-on-accent)] rounded-full animate-spin" />
                  <span>Provisioning Workspace...</span>
                </>
              ) : (
                <>
                  <span>Create Organization Account</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>

          <div className="border-t border-[var(--sd-border)] pt-4 text-center">
            <p className="text-[13px] text-[var(--sd-text-muted)]">
              Already have an organization?{" "}
              <Link
                href={`/login${rawRedirect ? `?redirect=${encodeURIComponent(rawRedirect)}` : ""}`}
                className="text-[var(--sd-pine)] font-medium hover:underline transition ml-1"
              >
                Sign In to Console
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function SignupPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[var(--sd-bg)] flex items-center justify-center text-sm text-[var(--sd-text-muted)]">
          Loading ShieldDesk registration...
        </div>
      }
    >
      <SignupForm />
    </Suspense>
  );
}
