"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
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
} from "lucide-react";
import { DEV_USERS, type DevUserId } from "@/lib/context/ChatContext";
import { cn } from "@/lib/utils";
import { supabase, isSupabaseConfigured } from "@/lib/supabase/client";

export default function LoginPage() {
  const router = useRouter();

  const [authMode, setAuthMode] = useState<"credentials" | "register" | "quick" | "supabase">("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [selectedUser, setSelectedUser] = useState<DevUserId>("dev-analyst");
  const [mfaCode, setMfaCode] = useState("482910");
  const [agreedToTerms, setAgreedToTerms] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreedToTerms) {
      setErrorMessage("You must accept the Autonomous Security & DPA Terms.");
      return;
    }

    setLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      if (authMode === "register") {
        const res = await fetch("/api/auth/signup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, organizationName: orgName }),
        });
        const data = await res.json();
        if (res.ok) {
          setSuccessMessage("Tenant registered successfully. Redirecting to SOC...");
          setTimeout(() => router.push("/"), 1200);
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
            setErrorMessage(`Supabase Auth: ${error.message}`);
          } else {
            setSuccessMessage(`Authenticated via Supabase as ${data.user?.email || "Operator"}! Redirecting...`);
            setTimeout(() => router.push("/"), 1000);
          }
        }
      } else if (authMode === "credentials") {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, mfaCode }),
        });
        const data = await res.json();
        if (res.ok) {
          router.push("/");
        } else {
          setErrorMessage(data.error || "Authentication failed");
        }
      } else {
        // Quick Persona Login
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId: selectedUser, mfaCode }),
        });
        const data = await res.json();
        if (res.ok) {
          router.push("/");
        } else {
          setErrorMessage(data.error || "Authentication failed");
        }
      }
    } catch {
      setErrorMessage("Network error connecting to authentication gateway");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col justify-center items-center p-4 font-sans selection:bg-[var(--sd-pine)] selection:text-[#f7f4ed] relative">
      {/* Background ambient radial glow */}
      <div className="fixed inset-0 pointer-events-none sd-ambient-glow" />

      <div className="relative w-full max-w-md flex flex-col gap-6 z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center gap-3">
          <div className="h-16 w-16 rounded-2xl bg-white border border-[var(--sd-border)] p-1.5 flex items-center justify-center shadow-lg shadow-[var(--sd-pine)]/15 overflow-hidden">
            <img src="/logo.png" alt="ShieldDesk" className="h-full w-full object-contain" />
          </div>
          <div>
            <div className="flex items-center justify-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight text-[var(--sd-text)]">
                Shield<span className="text-[#a48858]">Desk</span><span className="text-[10px] text-[#a48858] align-super">™</span>
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--sd-panel)] text-[var(--sd-pine)] border border-[var(--sd-border)] uppercase tracking-wider font-mono shadow-xs">
                SOC v2.5
              </span>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] mt-1">
              AI-Powered Security Operations · A Product by Mints Global
            </p>
          </div>
        </div>

        {/* Auth Mode Tabs */}
        <div className="p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] grid grid-cols-4 gap-1 text-[11px]">
          <button
            type="button"
            onClick={() => { setAuthMode("credentials"); setErrorMessage(null); }}
            className={cn(
              "py-1.5 rounded-lg font-medium transition cursor-pointer text-center",
              authMode === "credentials"
                ? "bg-[var(--sd-panel)] text-[var(--sd-text)] shadow-xs font-semibold"
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
                ? "bg-[var(--sd-panel)] text-[var(--sd-pine)] shadow-xs font-semibold"
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
                ? "bg-[var(--sd-panel)] text-[var(--sd-text)] shadow-xs font-semibold"
                : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            Register
          </button>
          <button
            type="button"
            onClick={() => { setAuthMode("quick"); setErrorMessage(null); }}
            className={cn(
              "py-1.5 rounded-lg font-medium transition cursor-pointer text-center",
              authMode === "quick"
                ? "bg-[var(--sd-panel)] text-[var(--sd-text)] shadow-xs font-semibold"
                : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            Persona
          </button>
        </div>

        {/* Login Card */}
        <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xl backdrop-blur-md flex flex-col gap-5">
          <div className="border-b border-[var(--sd-border)] pb-3">
            <h2 className="text-sm font-bold text-[var(--sd-text)]">
              {authMode === "register"
                ? "Register New Tenant Organization"
                : authMode === "supabase"
                  ? "Supabase Cloud Authentication"
                  : authMode === "credentials"
                    ? "Operator Sign In"
                    : "Quick Persona Switcher"}
            </h2>
            <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
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
            <div className="p-3 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] text-xs flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--sd-danger)]" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="p-3 rounded-xl border border-[var(--sd-pine)]/30 bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] text-xs flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--sd-pine)]" />
              <span>{successMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {authMode === "register" && (
              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
                  <Building2 className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  <span>Organization Name</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Cybersecurity Corp"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)]"
                />
              </div>
            )}

            {authMode === "supabase" && (
              <div className="p-2.5 rounded-lg border border-[var(--sd-pine-border)] bg-[var(--sd-pine-dim)] text-[11px] text-[var(--sd-pine-bright)] flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-medium">
                  <Cloud className="h-3.5 w-3.5" />
                  SHIELD-DESK (dpuotfxyfqvwggewczhs)
                </span>
                <span className="font-mono text-[10px]">Cloud Auth Active</span>
              </div>
            )}

            {(authMode === "credentials" || authMode === "register" || authMode === "supabase") && (
              <>
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
                    <Mail className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                    <span>Corporate Email</span>
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="analyst@enterprise.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)]"
                  />
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
                    <KeyRound className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                    <span>Master Password</span>
                  </label>
                  <input
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)] font-mono"
                  />
                </div>
              </>
            )}

            {authMode === "quick" && (
              <div className="flex flex-col gap-1.5">
                <label className="text-[11px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
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
                          "p-3 rounded-xl border transition-all duration-150 cursor-pointer flex items-center justify-between text-xs",
                          isSelected
                            ? "border-[var(--sd-pine)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)] font-semibold shadow-xs"
                            : "border-[var(--sd-border)] bg-[var(--sd-bg)]/60 hover:bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)]"
                        )}
                      >
                        <div className="flex items-center gap-2.5">
                          <div
                            className={cn(
                              "h-2 w-2 rounded-full",
                              userId === "dev-admin"
                                ? "bg-[#9333ea]"
                                : userId === "dev-other"
                                  ? "bg-[#d97706]"
                                  : "bg-[var(--sd-pine-bright)]"
                            )}
                          />
                          <div className="flex flex-col">
                            <span className="font-medium text-[var(--sd-text)]">{u.label}</span>
                            <span className="text-[10px] text-[var(--sd-text-muted)] font-normal">
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
                <label className="text-[11px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
                  <Fingerprint className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  <span>Hardware MFA / TOTP Token</span>
                </label>
                <span className="text-[10px] text-[var(--sd-pine)] font-mono font-semibold">FIDO2 Active</span>
              </div>
              <input
                type="text"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                maxLength={6}
                className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-sm font-mono tracking-widest text-center focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)] selection:bg-[var(--sd-pine)] selection:text-[#f7f4ed]"
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
              className="mt-1 w-full py-2.5 px-4 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/90 text-[#f7f4ed] text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-[var(--sd-pine)]/15 cursor-pointer disabled:opacity-50"
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

        {/* Security Footer Notice */}
        <div className="text-center text-[10px] text-[var(--sd-text-dim)] flex items-center justify-center gap-2 font-mono">
          <Lock className="h-3 w-3" />
          <span>mTLS Encrypted &bull; ISO 27001 / SOC 2 Type II Certified Session</span>
        </div>
      </div>
    </div>
  );
}
