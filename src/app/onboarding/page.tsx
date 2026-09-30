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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between p-6">
      {/* Header */}
      <header className="max-w-4xl mx-auto w-full flex items-center justify-between py-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
            <Shield className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <span className="font-bold text-lg tracking-wider text-slate-100">SHIELD<span className="text-emerald-400">DESK</span></span>
            <span className="ml-2 px-2 py-0.5 text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded">SOC Onboarding</span>
          </div>
        </div>

        {/* Progress Tracker */}
        <div className="flex items-center gap-2 text-xs font-mono">
          {[1, 2, 3, 4].map((s) => (
            <div 
              key={s} 
              className={`w-7 h-7 rounded-full flex items-center justify-center font-bold border transition-colors ${
                step === s 
                  ? "bg-emerald-500 text-slate-950 border-emerald-400 shadow-lg shadow-emerald-500/20" 
                  : step > s 
                    ? "bg-emerald-950/80 text-emerald-400 border-emerald-800" 
                    : "bg-slate-900 text-slate-500 border-slate-800"
              }`}
            >
              {step > s ? "✓" : s}
            </div>
          ))}
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-2xl mx-auto w-full my-8 bg-slate-900/60 border border-slate-800/80 rounded-2xl p-8 backdrop-blur shadow-2xl">
        {step === 1 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Server className="w-8 h-8 text-emerald-400" />
              <div>
                <h1 className="text-xl font-bold text-slate-100">Set Up Your Security Organization</h1>
                <p className="text-xs text-slate-400">Configure your tenant workspace boundary and compliance baseline.</p>
              </div>
            </div>

            <div className="space-y-4 pt-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-2">Organization Name</label>
                <input 
                  type="text" 
                  value={orgName} 
                  onChange={(e) => setOrgName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-slate-100 font-medium focus:border-emerald-500 focus:outline-none transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-2">Data Residency & Region</label>
                <select className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-slate-100 font-medium focus:border-emerald-500 focus:outline-none">
                  <option value="us-east-1">US East (N. Virginia) • FIPS-140-2 Encrypted</option>
                  <option value="eu-central-1">EU Central (Frankfurt) • GDPR Compliant</option>
                  <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                </select>
              </div>
            </div>

            <button 
              onClick={() => setStep(2)}
              className="w-full mt-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg flex items-center justify-center gap-2 transition-all shadow-lg shadow-emerald-500/10 cursor-pointer"
            >
              Continue to MFA Enrollment <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Lock className="w-8 h-8 text-amber-400" />
              <div>
                <h1 className="text-xl font-bold text-slate-100">Mandatory Multi-Factor Authentication</h1>
                <p className="text-xs text-slate-400">Required by SOC 2 and ISO 27001 for all administrative and approver accounts.</p>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-4">
              <div className="flex items-center gap-4">
                <div className="w-24 h-24 bg-white p-2 rounded-lg flex items-center justify-center">
                  <div className="w-20 h-20 bg-slate-950 flex items-center justify-center rounded">
                    <span className="text-[9px] text-emerald-400 font-mono text-center">QR CODE<br/>TOTP AUTH</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-slate-300">Secret Key for Manual Entry:</p>
                  <code className="text-xs font-mono bg-slate-900 px-2 py-1 rounded text-amber-400 border border-slate-800">
                    JBSWY3DPEHPK3PXP
                  </code>
                  <p className="text-[11px] text-slate-500 pt-1">Scan using 1Password, Google Authenticator, or Bitwarden.</p>
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Enter 6-digit confirmation code</label>
                <input 
                  type="text" 
                  maxLength={6}
                  placeholder="123456"
                  value={mfaCode}
                  onChange={(e) => {
                    setMfaCode(e.target.value);
                    if (e.target.value.length === 6) setMfaVerified(true);
                  }}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 font-mono text-center tracking-widest text-lg text-emerald-400 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button 
                onClick={() => setStep(1)}
                className="py-3 px-5 border border-slate-700 hover:bg-slate-800 rounded-lg text-xs font-semibold cursor-pointer"
              >
                Back
              </button>
              <button 
                onClick={() => setStep(3)}
                disabled={!mfaVerified && mfaCode.length < 6}
                className="flex-1 py-3 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold rounded-lg flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                Verify & Next <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Terminal className="w-8 h-8 text-emerald-400" />
              <div>
                <h1 className="text-xl font-bold text-slate-100">Deploy Universal Endpoint Agent</h1>
                <p className="text-xs text-slate-400">Install the lightweight Go daemon to begin telemetry streaming and autonomous triage.</p>
              </div>
            </div>

            <div className="flex gap-2 border-b border-slate-800 pb-2">
              <button 
                onClick={() => setOsTab("windows")}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  osTab === "windows" 
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" 
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Laptop className="w-4 h-4" /> Windows (PowerShell)
              </button>
              <button 
                onClick={() => setOsTab("linux")}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  osTab === "linux" 
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" 
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Server className="w-4 h-4" /> Linux (systemd)
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-mono">1-Line Automated Installer Command</span>
                <button 
                  onClick={() => copyToClipboard(osTab === "windows" ? windowsCmd : linuxCmd)}
                  className="flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300 font-mono text-xs cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" /> {copied ? "Copied!" : "Copy Command"}
                </button>
              </div>
              <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto select-all">
                {osTab === "windows" ? windowsCmd : linuxCmd}
              </div>
              <p className="text-[11px] text-slate-500">
                • Automatically issues a scoped X.509 client certificate.<br/>
                • Registers as an auto-restarting background OS service.
              </p>
            </div>

            <div className="flex gap-3">
              <button 
                onClick={() => setStep(2)}
                className="py-3 px-5 border border-slate-700 hover:bg-slate-800 rounded-lg text-xs font-semibold cursor-pointer"
              >
                Back
              </button>
              <button 
                onClick={() => setStep(4)}
                className="flex-1 py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                I Have Run the Command <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-6 text-center py-4">
            <div className="w-16 h-16 bg-emerald-500/10 border border-emerald-500/30 rounded-full flex items-center justify-center mx-auto text-emerald-400">
              <CheckCircle className="w-8 h-8 animate-pulse" />
            </div>

            <div className="space-y-2">
              <h1 className="text-2xl font-bold text-slate-100">Endpoint Protected & Connected!</h1>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Your first agent has successfully enrolled into tenant <span className="text-emerald-400 font-mono">{orgName}</span>. 
                Streaming telemetry is live and cryptographic response channels are verified.
              </p>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-left font-mono text-xs space-y-2 max-w-md mx-auto">
              <div className="flex justify-between">
                <span className="text-slate-500">Host Status:</span>
                <span className="text-emerald-400">ONLINE (mTLS Active)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Autonomy Tier:</span>
                <span className="text-slate-300">Tier 2 Governed Response</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Audit Ledger:</span>
                <span className="text-emerald-400">SHA-256 Chain Synchronized</span>
              </div>
            </div>

            <Link 
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2 py-3 px-8 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-lg transition-all shadow-lg shadow-emerald-500/20"
            >
              Enter ShieldDesk SOC Console <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="max-w-4xl mx-auto w-full text-center text-xs text-slate-600 py-2">
        ShieldDesk Enterprise Autonomous SOC • Zero-Trust Governed Remediation Platform
      </footer>
    </div>
  );
}
