"use client";


import React, { useState } from "react";
import Link from "next/link";
import {
  Shield,
  Key,
  Terminal,
  CheckCircle,
  Copy,
  ArrowRight,
  Laptop,
  Lock,
  RefreshCw,
  Server
} from "lucide-react";

export default function OnboardingPage() {
  const [step, setStep] = useState(1);
  const [orgName, setOrgName] = useState("Acme Cybersecurity");
  const [osTab, setOsTab] = useState<"windows" | "linux">("windows");
  const [copied, setCopied] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaVerified, setMfaVerified] = useState(false);

  const mockToken = "sdt_secops_live_9f83a2c07e1";
  const controlPlaneUrl = "https://control.shielddesk.io";

  const windowsCmd = `powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '${controlPlaneUrl}/install-windows.ps1' -OutFile 'install.ps1'; .\\install.ps1 -ControlPlane '${controlPlaneUrl}' -EnrollToken '${mockToken}'"`;
  const linuxCmd = `curl -sSL ${controlPlaneUrl}/install.sh | sudo bash -s -- --control-plane "${controlPlaneUrl}" --token "${mockToken}"`;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col justify-between p-6 font-sans">
      {/* Header */}
      <header className="max-w-4xl mx-auto w-full flex flex-wrap items-center justify-between gap-4 py-4 border-b border-[var(--sd-border)]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 p-1 bg-[var(--sd-pine-dim)] border border-[var(--sd-pine-border)] rounded-lg flex items-center justify-center">
            <img src="/favicon/apple-touch-icon.png" alt="ShieldDesk" className="w-full h-full object-contain" />
          </div>
          <div>
            <span className="font-medium text-lg tracking-wider text-[var(--sd-text)]">SHIELD<span className="text-[var(--sd-wheat)]">DESK</span></span>
            <span className="ml-2 px-2 py-0.5 text-[13px] font-medium bg-[var(--sd-pine-dim)] text-[var(--sd-wheat)] border border-[var(--sd-pine-border)] rounded">SOC Onboarding · Demo</span>
          </div>
        </div>

        {/* Progress Tracker */}
        <div className="flex items-center gap-2 text-[13px] font-mono">
          {[1, 2, 3, 4].map((s) => (
            <div
              key={s}
              className={`w-7 h-7 rounded-full flex items-center justify-center font-medium border transition-colors ${
                step === s
                  ? "bg-[var(--sd-gold)] text-[var(--sd-on-accent)] border-[var(--sd-wheat)] shadow-lg "
                  : step > s
                    ? "bg-[var(--sd-success-dim)] text-[var(--sd-wheat)] border-[var(--sd-border)]"
                    : "bg-[var(--sd-panel-raised)] text-[var(--sd-text-dim)] border-[var(--sd-border)]"
              }`}
            >
              {step > s ? "✓" : s}
            </div>
          ))}
        </div>
      </header>

      <p className="max-w-2xl mx-auto mt-8 text-[13px] text-[var(--sd-text-muted)]">Sample onboarding walkthrough. The enrollment token, MFA secret, and connection status below are illustrative.</p>

      {/* Main Content Area */}
      <main className="max-w-2xl mx-auto w-full my-8 sd-surface border border-[var(--sd-border)] rounded-2xl p-8 shadow-2xl">
        {step === 1 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Server className="w-8 h-8 text-[var(--sd-wheat)]" />
              <div>
                <h1 className="text-[var(--sd-text)] text-3xl font-light leading-tight">Set Up Your Security Organization</h1>
                <p className="text-[13px] text-[var(--sd-text-muted)]">Configure your tenant workspace boundary and compliance baseline.</p>
              </div>
            </div>

            <div className="space-y-4 pt-4">
              <div>
                <label className="block text-[13px] font-mono text-[var(--sd-text-muted)] uppercase tracking-wider mb-2">Organization Name</label>
                <input
                  aria-label="Organization name"
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="sd-input w-full bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-lg px-4 py-3 text-[var(--sd-text)] font-medium focus:border-[var(--sd-wheat)] focus:outline-none transition-colors"
                />
              </div>

              <div>
                <label className="block text-[13px] font-mono text-[var(--sd-text-muted)] uppercase tracking-wider mb-2">Data Residency & Region</label>
                <select aria-label="Data residency and region" className="sd-input w-full bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-lg px-4 py-3 text-[var(--sd-text)] font-medium focus:border-[var(--sd-wheat)] focus:outline-none">
                  <option value="us-east-1">US East (N. Virginia) • FIPS-140-2 Encrypted</option>
                  <option value="eu-central-1">EU Central (Frankfurt) • GDPR Compliant</option>
                  <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                </select>
              </div>
            </div>

            <button
              onClick={() => setStep(2)}
              className="sd-button w-full mt-6 py-3 bg-[var(--sd-gold)] hover:bg-[var(--sd-wheat)] text-[var(--sd-on-accent)] font-medium rounded-full flex items-center justify-center gap-2 transition-all shadow-lg  cursor-pointer"
            >
              Continue to MFA Enrollment <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Lock className="w-8 h-8 text-[var(--sd-warning)]" />
              <div>
                <h1 className="text-[var(--sd-text)] text-3xl font-light leading-tight">Mandatory Multi-Factor Authentication</h1>
                <p className="text-[13px] text-[var(--sd-text-muted)]">Required by SOC 2 and ISO 27001 for all administrative and approver accounts.</p>
              </div>
            </div>

            <div className="p-4 bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl space-y-4">
              <div className="flex flex-wrap items-center gap-4">
                <div className="w-24 h-24 sd-surface p-2 rounded-lg flex items-center justify-center">
                  <div className="w-20 h-20 bg-[var(--sd-bg)] flex items-center justify-center rounded">
                    <span className="text-[11px] text-[var(--sd-wheat)] font-mono text-center">QR CODE<br/>TOTP AUTH</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-[13px] text-[var(--sd-text-muted)]">Secret Key for Manual Entry:</p>
                  <code className="text-[13px] font-mono bg-[var(--sd-panel-raised)] px-2 py-1 rounded text-[var(--sd-warning)] border border-[var(--sd-border)]">
                    JBSWY3DPEHPK3PXP
                  </code>
                  <p className="text-[11px] text-[var(--sd-text-dim)] pt-1">Scan using 1Password, Google Authenticator, or Bitwarden.</p>
                </div>
              </div>

              <div>
                <label className="block text-[13px] font-mono text-[var(--sd-text-muted)] mb-1">Enter 6-digit confirmation code</label>
                <input
                  type="text"
                  aria-label="Six-digit demo confirmation code"
                  maxLength={6}
                  placeholder="123456"
                  value={mfaCode}
                  onChange={(e) => {
                    setMfaCode(e.target.value);
                    if (e.target.value.length === 6) setMfaVerified(true);
                  }}
                  className="sd-input w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-lg px-4 py-2 font-mono text-center tracking-widest text-lg text-[var(--sd-wheat)] focus:outline-none focus:border-[var(--sd-wheat)]"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setStep(1)}
                className="sd-button py-3 px-5 border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] rounded-full text-[13px] font-medium cursor-pointer"
              >
                Back
              </button>
              <button
                onClick={() => setStep(3)}
                disabled={!mfaVerified && mfaCode.length < 6}
                className="sd-button flex-1 py-3 bg-[var(--sd-gold)] hover:bg-[var(--sd-wheat)] disabled:opacity-50 text-[var(--sd-on-accent)] font-medium rounded-full flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                Verify & Next <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Terminal className="w-8 h-8 text-[var(--sd-wheat)]" />
              <div>
                <h1 className="text-[var(--sd-text)] text-3xl font-light leading-tight">Deploy Universal Endpoint Agent</h1>
                <p className="text-[13px] text-[var(--sd-text-muted)]">Install the lightweight Go daemon to begin telemetry streaming and autonomous triage.</p>
              </div>
            </div>

            <div className="flex flex-wrap gap-2 border-b border-[var(--sd-border)] pb-2">
              <button
                onClick={() => setOsTab("windows")}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-[13px] font-medium transition-colors cursor-pointer ${
                  osTab === "windows"
                    ? "bg-[var(--sd-pine-dim)] text-[var(--sd-wheat)] border border-[var(--sd-pine-border)]"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                }`}
              >
                <Laptop className="w-4 h-4" /> Windows (PowerShell)
              </button>
              <button
                onClick={() => setOsTab("linux")}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-[13px] font-medium transition-colors cursor-pointer ${
                  osTab === "linux"
                    ? "bg-[var(--sd-pine-dim)] text-[var(--sd-wheat)] border border-[var(--sd-pine-border)]"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                }`}
              >
                <Server className="w-4 h-4" /> Linux (systemd)
              </button>
            </div>

            <div className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between text-[13px] text-[var(--sd-text-muted)]">
                <span className="font-mono">1-Line Automated Installer Command</span>
                <button
                  onClick={() => copyToClipboard(osTab === "windows" ? windowsCmd : linuxCmd)}
                  className="sd-button flex items-center gap-1.5 text-[var(--sd-wheat)] hover:text-[var(--sd-wheat)] font-mono text-[13px] cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" /> {copied ? "Copied!" : "Copy Command"}
                </button>
              </div>
              <div className="bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] rounded-lg p-3 font-mono text-[13px] text-[var(--sd-text-muted)] overflow-x-auto select-all">
                {osTab === "windows" ? windowsCmd : linuxCmd}
              </div>
              <p className="text-[11px] text-[var(--sd-text-dim)]">
                • Automatically issues a scoped X.509 client certificate.<br/>
                • Registers as an auto-restarting background OS service.
              </p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setStep(2)}
                className="sd-button py-3 px-5 border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] rounded-full text-[13px] font-medium cursor-pointer"
              >
                Back
              </button>
              <button
                onClick={() => setStep(4)}
                className="sd-button flex-1 py-3 bg-[var(--sd-gold)] hover:bg-[var(--sd-wheat)] text-[var(--sd-on-accent)] font-medium rounded-full flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                I Have Run the Command <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-6 text-center py-4">
            <div className="w-16 h-16 bg-[var(--sd-pine-dim)] border border-[var(--sd-pine-border)] rounded-full flex items-center justify-center mx-auto text-[var(--sd-wheat)]">
              <CheckCircle className="w-8 h-8 animate-pulse" />
            </div>

            <div className="space-y-2">
              <h1 className="text-[var(--sd-text)] text-3xl font-light leading-tight">Endpoint Protected & Connected!</h1>
              <p className="text-[13px] text-[var(--sd-text-muted)] max-w-md mx-auto">
                Your first agent has successfully enrolled into tenant <span className="text-[var(--sd-wheat)] font-mono">{orgName}</span>.
                Streaming telemetry is live and cryptographic response channels are verified.
              </p>
            </div>

            <div className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl p-4 text-left font-mono text-[13px] space-y-2 max-w-md mx-auto">
              <div className="flex justify-between">
                <span className="text-[var(--sd-text-dim)]">Host Status:</span>
                <span className="text-[var(--sd-wheat)]">ONLINE (mTLS Active)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--sd-text-dim)]">Autonomy Tier:</span>
                <span className="text-[var(--sd-text-muted)]">Tier 2 Governed Response</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--sd-text-dim)]">Audit Ledger:</span>
                <span className="text-[var(--sd-wheat)]">SHA-256 Chain Synchronized</span>
              </div>
            </div>

            <Link
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2 py-3 px-8 bg-[var(--sd-gold)] hover:bg-[var(--sd-wheat)] text-[var(--sd-on-accent)] font-medium rounded-lg transition-all shadow-lg "
            >
              Enter ShieldDesk SOC Console <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="max-w-4xl mx-auto w-full text-center text-[13px] text-[var(--sd-text-dim)] py-2">
        ShieldDesk Enterprise Autonomous SOC • Zero-Trust Governed Remediation Platform
      </footer>
    </div>
  );
}
