"use client";

import React, { useState } from "react";
import {
  Fingerprint,
  QrCode,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldOff,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";

type MfaStep = "idle" | "scanning" | "confirming" | "enrolled" | "disabling";

interface MfaSetupPanelProps {
  /** Whether the user currently has TOTP enrolled (pass from your user profile API). */
  initialEnrolled?: boolean;
}

/**
 * Self-contained MFA enrollment / disable panel.
 *
 * Flow:
 *   1. User clicks "Enable MFA" → GET /api/auth/mfa/setup → shows QR code
 *   2. User scans with authenticator app and enters the 6-digit code
 *   3. POST /api/auth/mfa/setup { code } → server verifies + commits secret
 *   4. Panel shows "MFA Active" state with option to disable
 */
export function MfaSetupPanel({ initialEnrolled = false }: MfaSetupPanelProps) {
  const [enrolled, setEnrolled] = useState(initialEnrolled);
  const [step, setStep] = useState<MfaStep>("idle");
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // ── Step 1: Fetch QR ─────────────────────────────────────────────────────
  const startEnrollment = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch("/api/auth/mfa/setup");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start MFA enrollment.");
      setQrDataUrl(data.qrDataUrl);
      setStep("scanning");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  // ── Step 2: Confirm code ──────────────────────────────────────────────────
  const confirmCode = async () => {
    if (!/^\d{6}$/.test(code)) {
      setErrorMsg("Please enter a 6-digit code from your authenticator app.");
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch("/api/auth/mfa/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "MFA confirmation failed.");
      setEnrolled(true);
      setStep("enrolled");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  // ── Disable MFA ───────────────────────────────────────────────────────────
  const disableMfa = async () => {
    if (!/^\d{6}$/.test(disableCode)) {
      setErrorMsg("Enter your current 6-digit TOTP code to disable MFA.");
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch("/api/auth/mfa/setup", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: disableCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to disable MFA.");
      setEnrolled(false);
      setStep("idle");
      setDisableCode("");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] flex flex-col gap-4 shadow-xs max-w-md">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-[var(--sd-border)] pb-4">
        <div
          className={cn(
            "h-9 w-9 rounded-xl flex items-center justify-center shadow-xs",
            enrolled
              ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)]"
              : "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)]"
          )}
        >
          {enrolled ? <ShieldCheck className="h-5 w-5" /> : <Fingerprint className="h-5 w-5" />}
        </div>
        <div>
          <h2 className="text-sm font-bold text-[var(--sd-text)]">
            Two-Factor Authentication (TOTP)
          </h2>
          <p className="text-xs text-[var(--sd-text-muted)]">
            {enrolled ? "MFA is active on your account." : "Add a second layer of protection."}
          </p>
        </div>
        <span
          className={cn(
            "ml-auto px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider",
            enrolled
              ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]"
              : "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
          )}
        >
          {enrolled ? "Active" : "Not Enrolled"}
        </span>
      </div>

      {/* Error Banner */}
      {errorMsg && (
        <div className="p-3 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] text-xs flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* ── Idle / Not enrolled ──────────────────────────────────────────── */}
      {!enrolled && step === "idle" && (
        <div className="flex flex-col gap-3">
          <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
            Use any TOTP-compatible authenticator app (Google Authenticator, Authy, 1Password) to
            secure your account. A 6-digit code will be required on every login.
          </p>
          <button
            onClick={startEnrollment}
            disabled={loading}
            className="flex items-center justify-center gap-2 w-full py-2 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/90 text-[#f7f4ed] text-xs font-bold transition cursor-pointer disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <QrCode className="h-3.5 w-3.5" />}
            <span>Enable MFA</span>
          </button>
        </div>
      )}

      {/* ── QR Scan step ─────────────────────────────────────────────────── */}
      {step === "scanning" && qrDataUrl && (
        <div className="flex flex-col gap-4 items-center">
          <p className="text-xs text-[var(--sd-text-muted)] text-center leading-relaxed">
            Scan this QR code with your authenticator app, then enter the 6-digit code below.
          </p>
          <img
            src={qrDataUrl}
            alt="TOTP QR code — scan with your authenticator app"
            className="w-48 h-48 rounded-xl border border-[var(--sd-border)] shadow-xs"
          />
          <div className="flex flex-col gap-2 w-full">
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="Enter 6-digit code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3 py-2 text-sm font-mono tracking-widest text-center focus:outline-none focus:border-[var(--sd-pine)] text-[var(--sd-text)]"
            />
            <button
              onClick={confirmCode}
              disabled={loading || code.length !== 6}
              className="flex items-center justify-center gap-2 w-full py-2 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/90 text-[#f7f4ed] text-xs font-bold transition cursor-pointer disabled:opacity-50"
            >
              {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
              <span>Verify & Activate MFA</span>
            </button>
          </div>
        </div>
      )}

      {/* ── Success & Disabling ────────────────────────────────────────── */}
      {(step === "enrolled" || step === "disabling" || (enrolled && step === "idle")) && (
        <div className="flex flex-col gap-3">
          <div className="p-3 rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] text-[var(--sd-success)] text-xs flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>MFA is active. Your account requires a TOTP code on every login.</span>
          </div>

          {/* Disable toggle */}
          {step !== "disabling" && (
            <button
              onClick={() => { setStep("disabling"); setErrorMsg(null); }}
              className="flex items-center justify-center gap-2 w-full py-2 rounded-xl border border-[var(--sd-danger-border)] text-[var(--sd-danger)] text-xs font-semibold hover:bg-[var(--sd-danger-dim)] transition cursor-pointer"
            >
              <ShieldOff className="h-3.5 w-3.5" />
              <span>Disable MFA</span>
            </button>
          )}

          {step === "disabling" && (
            <div className="flex flex-col gap-2">
              <p className="text-xs text-[var(--sd-text-muted)]">
                Enter your current TOTP code to confirm removal:
              </p>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                placeholder="Current 6-digit code"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                className="bg-[var(--sd-bg)] border border-[var(--sd-danger-border)] rounded-xl px-3 py-2 text-sm font-mono tracking-widest text-center focus:outline-none text-[var(--sd-text)]"
              />
              <div className="flex gap-2">
                <button
                  onClick={() => { setStep("enrolled"); setErrorMsg(null); }}
                  className="flex-1 py-2 rounded-xl border border-[var(--sd-border)] text-[var(--sd-text-muted)] text-xs font-semibold hover:bg-[var(--sd-panel-raised)] transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={disableMfa}
                  disabled={loading || disableCode.length !== 6}
                  className="flex-1 flex items-center justify-center gap-2 py-2 rounded-xl bg-[var(--sd-danger)] text-white text-xs font-bold transition cursor-pointer disabled:opacity-50"
                >
                  {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5" />}
                  <span>Confirm Disable</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
