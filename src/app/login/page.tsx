"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Lock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Fingerprint,
  Mail,
  KeyRound,
  Building2,
  UserCheck,
  Cloud,
  Compass,
} from "lucide-react";
import { DEV_USERS, type DevUserId } from "@/lib/context/ChatContext";
import { cn } from "@/lib/utils";
import { supabase, isSupabaseConfigured } from "@/lib/supabase/client";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = searchParams.get("redirect") || "/";

  const [authMode, setAuthMode] = useState<"credentials" | "register" | "quick" | "supabase">("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [selectedUser, setSelectedUser] = useState<DevUserId>("dev-analyst");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [agreedToTerms, setAgreedToTerms] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [devPersonasAllowed, setDevPersonasAllowed] = useState(false);
  const [clientIp, setClientIp] = useState<string>("");

  useEffect(() => {
    // Detect genuine public client IP
    fetch("https://api.ipify.org?format=json")
      .then((res) => res.json())
      .then((data) => {
        if (data?.ip) setClientIp(data.ip);
      })
      .catch(() => {});

    fetch("/api/health")
      .then((res) => res.json())
      .then((data) => {
        if (data?.environment?.devPersonasAllowed !== undefined) {
          setDevPersonasAllowed(Boolean(data.environment.devPersonasAllowed));
        }
      })
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreedToTerms) {
      setErrorMessage("You must accept the Autonomous Security & DPA Terms.");
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
      if (authMode === "register") {
        const res = await fetch("/api/auth/signup", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({ email, password, organizationName: orgName, clientIp }),
        });
        const data = await res.json();
        if (res.ok) {
          setSuccessMessage("Tenant registered successfully. Redirecting to SOC...");
          setTimeout(() => router.push(redirectTarget), 1000);
        } else {
          setErrorMessage(data.error || "Registration failed");
        }
      } else if (authMode === "supabase") {
        if (!isSupabaseConfigured || !supabase) {
          setErrorMessage("Supabase cloud client is not configured.");
        } else {
          const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password,
          });
          if (error) {
            // Report to Threat Engine so it immediately appears in the Alerts tab
            try {
              const threatRes = await fetch("/api/threats", {
                method: "POST",
                headers: authHeaders,
                body: JSON.stringify({
                  action: "record_login_failure",
                  email,
                  clientIp: clientIp || undefined,
                  reason: `Supabase Auth: ${error.message}`,
                }),
              });
              const threatData = await threatRes.json();
              if (threatData?.isBlocked) {
                setErrorMessage("Too many login attempts. Contact security admin to unblock.");
              } else {
                setErrorMessage(`Supabase Auth: ${error.message}`);
              }
            } catch {
              setErrorMessage(`Supabase Auth: ${error.message}`);
            }
          } else {
            setSuccessMessage(`Authenticated via Supabase as ${data.user?.email || "Operator"}! Redirecting...`);
            setTimeout(() => router.push(redirectTarget), 800);
          }
        }
      } else if (authMode === "credentials") {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({ email, password, mfaCode: mfaCode || undefined, clientIp: clientIp || undefined }),
        });
        const data = await res.json();
        if (res.ok) {
          router.push(redirectTarget);
        } else {
          if (data.blocked) {
            setErrorMessage("Too many login attempts. Contact security admin to unblock.");
          } else if (data.mfaRequired) {
            setMfaRequired(true);
            setErrorMessage("Enter your 6-digit TOTP code from your authenticator app.");
          } else {
            setErrorMessage(data.error || "Authentication failed");
          }
        }
      } else {
        // Quick Persona Login (only available when devPersonasAllowed is true)
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({ userId: selectedUser, mfaCode, clientIp: clientIp || undefined }),
        });
        const data = await res.json();
        if (res.ok) {
          router.push(redirectTarget);
        } else {
          if (data.blocked) {
            setErrorMessage("Too many login attempts. Contact security admin to unblock.");
          } else {
            setErrorMessage(data.error || "Authentication failed");
          }
        }
      }
    } catch {
      setErrorMessage("Network error connecting to authentication gateway");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col justify-center items-center p-4 font-sans selection:bg-[var(--sd-pine)] selection:text-[var(--sd-on-accent)] relative">
      {/* Background ambient radial glow */}
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
                Shield<span className="text-[var(--sd-wheat)]">Desk</span><span className="text-[11px] text-[var(--sd-wheat)] align-super">™</span>
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-medium sd-surface text-[var(--sd-pine)] border border-[var(--sd-border)] uppercase tracking-wider font-mono shadow-xs">
                SOC v2.5
              </span>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
              AI-Powered Security Operations · A Product by Mints Global
            </p>
          </div>
        </div>

        {/* Auth Mode Tabs */}
        <div
          className={cn(
            "p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] grid gap-1 text-[11px]",
            devPersonasAllowed ? "grid-cols-4" : "grid-cols-3"
          )}
        >
          <button
            type="button"
            onClick={() => { setAuthMode("credentials"); setErrorMessage(null); }}
            className={cn(
              "py-1.5 rounded-lg font-medium transition cursor-pointer text-center",
              authMode === "credentials"
                ? "sd-surface text-[var(--sd-text)] shadow-xs font-medium"
                : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setAuthMode("supabase"); setErrorMessage(null); }}
            className={cn(
              "py-1.5 rounded-lg font-medium transition cursor-pointer text-center flex items-center justify-center gap-1",
              authMode === "supabase"
                ? "sd-surface text-[var(--sd-pine)] shadow-xs font-medium"
                : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Cloud className="h-3 w-3" />
            <span>Supabase</span>
          </button>
          <button
            type="button"
            onClick={() => { setAuthMode("register"); setErrorMessage(null); }}
            className={cn(
              "py-1.5 rounded-lg font-medium transition cursor-pointer text-center",
              authMode === "register"
                ? "sd-surface text-[var(--sd-text)] shadow-xs font-medium"
                : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            Register
          </button>
          {devPersonasAllowed && (
            <button
              type="button"
              onClick={() => { setAuthMode("quick"); setErrorMessage(null); }}
              className={cn(
                "py-1.5 rounded-lg font-medium transition cursor-pointer text-center",
                authMode === "quick"
                  ? "sd-surface text-[var(--sd-text)] shadow-xs font-medium"
                  : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
              )}
            >
              Persona
            </button>
          )}
        </div>

        {/* Login Card */}
        <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xl flex flex-col gap-5">
          <div className="border-b border-[var(--sd-border)] pb-3">
            <h2 className="text-sm font-medium text-[var(--sd-text)]">
              {authMode === "register"
                ? "Register New Tenant Organization"
                : authMode === "supabase"
                  ? "Supabase Cloud Authentication"
                  : authMode === "credentials"
                    ? "Operator Sign In"
                    : "Quick Persona Switcher"}
            </h2>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-0.5">
              {authMode === "register"
                ? "Provision a dedicated tenant workspace with automated autonomy tiers."
                : authMode === "supabase"
                  ? "Connect directly to your active Supabase cloud project (SHIELD-DESK)."
                  : authMode === "credentials"
                    ? "Enter your corporate credentials and hardware MFA token."
                    : "One-click identity simulation for multi-tenant and RBAC testing."}
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
            {authMode === "register" && (
              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                  <Building2 className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  <span>Organization Name</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Cybersecurity Corp"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="sd-input bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-[13px] focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)]"
                />
              </div>
            )}

            {authMode === "supabase" && (
              <div className="p-2.5 rounded-lg border border-[var(--sd-pine-border)] bg-[var(--sd-pine-dim)] text-[11px] text-[var(--sd-pine-bright)] flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-medium">
                  <Cloud className="h-3.5 w-3.5" />
                  SHIELD-DESK (dpuotfxyfqvwggewczhs)
                </span>
                <span className="font-mono text-[11px]">Cloud Auth Active</span>
              </div>
            )}

            {(authMode === "credentials" || authMode === "register" || authMode === "supabase") && (
              <>
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                    <Mail className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                    <span>Corporate Email</span>
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="analyst@enterprise.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="sd-input bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-[13px] focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)]"
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
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="sd-input bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-[13px] focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)] font-mono"
                  />
                </div>
              </>
            )}

            {authMode === "quick" && devPersonasAllowed && (
              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                  <UserCheck className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  <span>Select Test Identity</span>
                </label>
                <div className="grid grid-cols-1 gap-2">
                  {(Object.keys(DEV_USERS) as DevUserId[]).map((userId) => {
                    const u = DEV_USERS[userId];
                    const isSelected = selectedUser === userId;
                    return (
                      <div
                        key={userId}
                        onClick={() => setSelectedUser(userId)}
                        className={cn(
                          "p-3 rounded-xl border transition-all duration-150 cursor-pointer flex items-center justify-between text-[13px]",
                          isSelected
                            ? "border-[var(--sd-pine)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)] font-medium shadow-xs"
                            : "border-[var(--sd-border)] bg-[var(--sd-bg)]/60 hover:bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)]"
                        )}
                      >
                        <div className="flex items-center gap-2.5">
                          <div
                            className={cn(
                              "h-2 w-2 rounded-full",
                              u.role === "system_admin"
                                ? "bg-[var(--sd-wheat)]"
                                : u.role === "super_admin"
                                  ? "bg-[#f59e0b]"
                                  : u.role === "responder"
                                    ? "bg-[#60a5fa]"
                                    : "bg-[var(--sd-pine-bright)]"
                            )}
                          />
                          <div className="flex flex-col">
                            <span className="font-medium text-[var(--sd-text)]">{u.label}</span>
                            <span className="text-[11px] text-[var(--sd-text-muted)] font-normal">
                              Tenant: {u.tenantName} ({u.role})
                            </span>
                          </div>
                        </div>
                        {isSelected && <CheckCircle2 className="h-4 w-4 text-[var(--sd-pine)]" />}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* MFA Verification */}
            <div className="flex flex-col gap-1.5 pt-1">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                  <Fingerprint className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  <span>TOTP / Authenticator App</span>
                </label>
                <span className="text-[11px] text-[var(--sd-pine)] font-mono font-medium">
                  {mfaRequired ? "Code required ↓" : "Optional if enrolled"}
                </span>
              </div>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                maxLength={6}
                placeholder={mfaRequired ? "Enter 6-digit code" : "Leave blank if not enrolled"}
                className="sd-input bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-sm font-mono tracking-widest text-center focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)] selection:bg-[var(--sd-pine)] selection:text-[var(--sd-on-accent)]"
              />
            </div>

            {/* Legal Terms & Autonomous Opt-in */}
            <div className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] flex items-start gap-2.5 text-[11px] text-[var(--sd-text-muted)]">
              <input
                type="checkbox"
                id="terms"
                checked={agreedToTerms}
                onChange={(e) => setAgreedToTerms(e.target.checked)}
                className="mt-0.5 rounded border-[var(--sd-border)] text-[var(--sd-pine)] focus:ring-0 cursor-pointer accent-[var(--sd-pine)]"
              />
              <label htmlFor="terms" className="cursor-pointer leading-relaxed">
                I accept the <strong className="text-[var(--sd-text)]">Autonomous Containment SLA</strong>,{" "}
                <strong className="text-[var(--sd-text)]">DPA Data Handling Rules</strong>, and consent to
                Layer 4 separation-of-duties governance.
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="sd-button sd-button-primary mt-1 w-full py-2.5 px-4 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium transition flex items-center justify-center gap-2 shadow-lg shadow-[var(--sd-pine)]/15 cursor-pointer disabled:opacity-50"
            >
              <span>
                {loading
                  ? "Verifying Credentials..."
                  : authMode === "register"
                    ? "Provision Tenant & Enter SOC"
                    : "Authenticate & Enter SOC"}
              </span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </form>
        </div>

        {/* Guided Fleet Onboarding Link */}
        <div className="text-center">
          <Link
            href="/onboarding"
            className="text-[13px] text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] inline-flex items-center gap-1.5 font-medium transition"
          >
            <Compass className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
            <span>Setting up a new SOC team? Follow Guided Fleet Onboarding</span>
            <ArrowRight className="h-3 w-3" />
          </Link>
        </div>

        {/* Security Footer Notice */}
        <div className="text-center text-[11px] text-[var(--sd-text-dim)] flex items-center justify-center gap-2 font-mono">
          <Lock className="h-3 w-3" />
          <span>mTLS Encrypted &bull; ISO 27001 &amp; SOC 2 Readiness Architecture</span>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] flex items-center justify-center text-[13px] text-[var(--sd-text-muted)] font-mono">
          Loading ShieldDesk Gate...
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}
