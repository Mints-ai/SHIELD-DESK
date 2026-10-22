"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  KeyRound,
  Shield,
  Server,
  Terminal,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  Lock,
  Eye,
  EyeOff,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Info,
  Layers,
  ArrowRight,
  Radio,
  Globe,
  Database,
  Cpu,
  Clock,
  Sparkles,
  BookOpen,
} from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";

interface EnrollmentTokenItem {
  id: string;
  tenant_id: string;
  label?: string | null;
  expires_at: string;
  max_uses: number;
  used_count: number;
  created_at: string;
  created_by?: string;
  revoked_at?: string | null;
}

interface GeneratedTokenResult {
  token: string;
  tokenId: string;
  expiresAt: string;
  installCommands: {
    linux: string;
    powershell: string;
    msi: string;
  };
}

interface IntegrationKeysStatus {
  canManage?: boolean;
  role?: string;
  shodan: {
    configured: boolean;
    maskedKey: string | null;
    apiInfo?: {
      configured: boolean;
      plan?: string;
      queryCredits?: number;
      scanCredits?: number;
      error?: string;
    } | null;
  };
  hibp: {
    configured: boolean;
    maskedKey: string | null;
    status?: {
      configured: boolean;
      message?: string;
    };
  };
  ingest: {
    configured: boolean;
    key: string;
    endpoint: string;
  };
}

export default function IntegrationsAndTokensPage() {
  const { activeUserId, activeUser } = useChat();

  // Active Tab
  const [activeTab, setActiveTab] = useState<"agent-tokens" | "third-party-keys">("agent-tokens");

  // Agent Token Generator State
  const [tokensList, setTokensList] = useState<EnrollmentTokenItem[]>([]);
  const [tokenLoading, setTokenLoading] = useState(false);
  const [tokenLabel, setTokenLabel] = useState("");
  const [tokenExpiryHours, setTokenExpiryHours] = useState("24");
  const [generatedResult, setGeneratedResult] = useState<GeneratedTokenResult | null>(null);
  const [agentInstallTab, setAgentInstallTab] = useState<"linux" | "powershell" | "msi">("linux");
  const [tokenError, setTokenError] = useState<string | null>(null);

  // Third-Party Keys State
  const [keysStatus, setKeysStatus] = useState<IntegrationKeysStatus | null>(null);

  // RBAC: Only System Admin or Super Admin can add, update, or remove external threat intel keys
  const isAdmin =
    activeUser.role === "system_admin" ||
    activeUser.role === "super_admin" ||
    activeUserId === "dev-admin" ||
    activeUserId === "dev-super" ||
    keysStatus?.canManage === true;
  const [keysLoading, setKeysLoading] = useState(false);
  const [shodanInput, setShodanInput] = useState("");
  const [hibpInput, setHibpInput] = useState("");
  const [showShodanKey, setShowShodanKey] = useState(false);
  const [showHibpKey, setShowHibpKey] = useState(false);
  const [shodanTesting, setShodanTesting] = useState(false);
  const [hibpTesting, setHibpTesting] = useState(false);
  const [shodanFeedback, setShodanFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [hibpFeedback, setHibpFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // Copy feedback tracking
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Fetch Enrollment Tokens List
  const fetchTokens = useCallback(async () => {
    try {
      const res = await fetch("/api/fleet/enrollment-tokens", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        const data = await res.json();
        setTokensList(data.tokens || []);
      }
    } catch {
      // Fallback
    }
  }, [activeUserId]);

  // Fetch Third-Party Keys Status
  const fetchKeys = useCallback(async () => {
    setKeysLoading(true);
    try {
      const res = await fetch("/api/integrations/keys", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        const data = await res.json();
        setKeysStatus(data);
      }
    } catch {
      // Ignore
    } finally {
      setKeysLoading(false);
    }
  }, [activeUserId]);

  useEffect(() => {
    fetchTokens();
    fetchKeys();
  }, [fetchTokens, fetchKeys]);

  // 1-Click Generate Agent Enrollment Token
  const handleGenerateToken = async () => {
    setTokenLoading(true);
    setTokenError(null);
    try {
      const res = await fetch("/api/fleet/enrollment-tokens", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          label: tokenLabel.trim() || `Agent deployment for ${activeUser.tenantName}`,
          expiresInHours: Number(tokenExpiryHours) || 24,
          maxUses: 1,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        setGeneratedResult({
          token: data.token,
          tokenId: data.tokenId,
          expiresAt: data.expiresAt,
          installCommands: data.installCommands,
        });
        setTokenLabel("");
        fetchTokens();
      } else {
        setTokenError(data.error || "Failed to generate enrollment token");
      }
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : "Network error");
    } finally {
      setTokenLoading(false);
    }
  };

  // Revoke Enrollment Token
  const handleRevokeToken = async (id: string) => {
    try {
      const res = await fetch(`/api/fleet/enrollment-tokens?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        fetchTokens();
      }
    } catch {
      // Ignore
    }
  };

  // Test & Save Shodan Key
  const handleSaveShodan = async (testOnly = false) => {
    if (!isAdmin) {
      setShodanFeedback({
        type: "error",
        message: "Forbidden: Only administrators (System Admin or Super Admin) can configure external intel keys.",
      });
      return;
    }
    if (!shodanInput.trim() && !keysStatus?.shodan.configured) return;
    setShodanTesting(true);
    setShodanFeedback(null);
    try {
      const res = await fetch("/api/integrations/keys", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          provider: "shodan",
          key: shodanInput.trim(),
          testOnly,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setShodanFeedback({
          type: "success",
          message: testOnly
            ? `Verified! Plan: ${data.apiInfo?.plan || "Community"} • ${data.apiInfo?.queryCredits ?? 0} query credits available.`
            : "Shodan API key saved successfully.",
        });
        if (!testOnly) {
          setShodanInput("");
          fetchKeys();
        }
      } else {
        setShodanFeedback({
          type: "error",
          message: data.error || "Invalid Shodan key or connectivity failure.",
        });
      }
    } catch (err) {
      setShodanFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "Request failed.",
      });
    } finally {
      setShodanTesting(false);
    }
  };

  // Remove Shodan Key
  const handleRemoveShodan = async () => {
    if (!isAdmin) {
      setShodanFeedback({
        type: "error",
        message: "Forbidden: Only administrators can remove external intel keys.",
      });
      return;
    }
    try {
      const res = await fetch("/api/integrations/keys?provider=shodan", {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        setShodanInput("");
        setShodanFeedback({ type: "success", message: "Shodan API key removed." });
        fetchKeys();
      } else {
        const data = await res.json().catch(() => ({}));
        setShodanFeedback({
          type: "error",
          message: data.error || "Failed to remove Shodan key.",
        });
      }
    } catch {
      // Ignore
    }
  };

  // Test & Save HIBP Key
  const handleSaveHibp = async (testOnly = false) => {
    if (!isAdmin) {
      setHibpFeedback({
        type: "error",
        message: "Forbidden: Only administrators (System Admin or Super Admin) can configure external intel keys.",
      });
      return;
    }
    if (!hibpInput.trim() && !keysStatus?.hibp.configured) return;
    setHibpTesting(true);
    setHibpFeedback(null);
    try {
      const res = await fetch("/api/integrations/keys", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          provider: "hibp",
          key: hibpInput.trim(),
          testOnly,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setHibpFeedback({
          type: "success",
          message: testOnly ? "HaveIBeenPwned API key format verified." : "HaveIBeenPwned API key saved.",
        });
        if (!testOnly) {
          setHibpInput("");
          fetchKeys();
        }
      } else {
        setHibpFeedback({
          type: "error",
          message: data.error || "Invalid HaveIBeenPwned key format.",
        });
      }
    } catch (err) {
      setHibpFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "Request failed.",
      });
    } finally {
      setHibpTesting(false);
    }
  };

  // Remove HIBP Key
  const handleRemoveHibp = async () => {
    if (!isAdmin) {
      setHibpFeedback({
        type: "error",
        message: "Forbidden: Only administrators can remove external intel keys.",
      });
      return;
    }
    try {
      const res = await fetch("/api/integrations/keys?provider=hibp", {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        setHibpInput("");
        setHibpFeedback({ type: "success", message: "HaveIBeenPwned API key removed." });
        fetchKeys();
      } else {
        const data = await res.json().catch(() => ({}));
        setHibpFeedback({
          type: "error",
          message: data.error || "Failed to remove HaveIBeenPwned key.",
        });
      }
    } catch {
      // Ignore
    }
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans selection:bg-[var(--sd-primary)] selection:text-white">
      <TopNavBar />

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-8">
        {/* Header Hero Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md relative overflow-hidden">
          <div className="absolute top-0 right-0 w-80 h-80 bg-[var(--sd-primary)]/10 rounded-full blur-3xl pointer-events-none" />

          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2 text-xs font-mono text-[var(--sd-wheat)] uppercase tracking-wider">
              <KeyRound className="w-4 h-4 text-[var(--sd-wheat)]" />
              <span>Security Credentials &amp; Connectors</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[var(--sd-sand)] tracking-tight">
              Tokens &amp; Integrations Command Center
            </h1>
            <p className="text-sm text-[var(--sd-text-muted)] leading-relaxed">
              Generate 1-click endpoint agent enrollment tokens to connect your host fleet, and optionally configure external threat intelligence keys (Shodan &amp; HIBP) to enrich attack surface telemetry.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/docs?doc=agent-installation-guide"
              className="sd-button flex items-center gap-2 px-4 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-wheat)] transition shadow-xs"
            >
              <BookOpen className="w-4 h-4" />
              <span>Agent Installation Runbook</span>
            </Link>
            <Link
              href="/dashboard/fleet"
              className="sd-button flex items-center gap-2 px-4 py-2.5 rounded-xl border border-[var(--sd-border-strong)] bg-[var(--sd-primary)] hover:bg-[var(--sd-primary-hover)] text-xs font-semibold text-white transition shadow-md"
            >
              <Server className="w-4 h-4" />
              <span>View Enrolled Fleet</span>
            </Link>
          </div>
        </div>

        {/* Executive Reassurance Banner (Zero AI Tokens Needed) */}
        <div className="p-4 sm:p-5 rounded-2xl border border-emerald-500/30 bg-emerald-950/20 flex items-start sm:items-center gap-3.5 shadow-xs">
          <div className="p-2 rounded-xl bg-emerald-900/40 border border-emerald-500/30 text-emerald-400 flex-shrink-0">
            <Sparkles className="w-4 h-4" />
          </div>
          <div className="flex-1 text-xs sm:text-sm text-[var(--sd-text)] leading-relaxed">
            <strong className="text-emerald-300 font-semibold">Native AI Co-Pilot Included: </strong>
            Your ShieldDesk subscription includes autonomous investigation reasoning and blast-radius modeling natively. You do <span className="underline decoration-emerald-500/50">not</span> need to supply OpenAI or external LLM tokens to use the SOC platform.
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-[var(--sd-border)] pb-2">
          <button
            onClick={() => setActiveTab("agent-tokens")}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition cursor-pointer ${
              activeTab === "agent-tokens"
                ? "bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] border border-[var(--sd-border)] shadow-xs"
                : "text-[var(--sd-text-dim)] hover:text-white hover:bg-[var(--sd-panel-raised)]"
            }`}
          >
            <Server className="w-4 h-4 text-emerald-400" />
            <span>Endpoint Agent Tokens (1-Click)</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-[var(--sd-wheat)]">
              {tokensList.length} Active
            </span>
          </button>

          <button
            onClick={() => setActiveTab("third-party-keys")}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition cursor-pointer ${
              activeTab === "third-party-keys"
                ? "bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] border border-[var(--sd-border)] shadow-xs"
                : "text-[var(--sd-text-dim)] hover:text-white hover:bg-[var(--sd-panel-raised)]"
            }`}
          >
            <Globe className="w-4 h-4 text-cyan-400" />
            <span>External Intel Keys (Shodan / HIBP)</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-[var(--sd-text-dim)]">
              Optional
            </span>
          </button>
        </div>

        {/* ─────────────────────────────────────────────────────────────────── */}
        {/* TAB 1: Endpoint Agent Tokens */}
        {/* ─────────────────────────────────────────────────────────────────── */}
        {activeTab === "agent-tokens" && (
          <div className="space-y-8">
            {/* 1-Click Token Generator Card */}
            <div className="p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[var(--sd-border-subtle)] pb-4">
                <div>
                  <h2 className="text-lg font-bold text-[var(--sd-sand)] flex items-center gap-2">
                    <Terminal className="w-5 h-5 text-[var(--sd-wheat)]" />
                    <span>Generate New Endpoint Enrollment Token</span>
                  </h2>
                  <p className="text-xs text-[var(--sd-text-muted)] mt-1">
                    Issues a cryptographically signed, tenant-bound token to register a new Linux, Windows, or macOS host to your SOC fleet.
                  </p>
                </div>

                <button
                  onClick={handleGenerateToken}
                  disabled={tokenLoading}
                  className="sd-button flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-[var(--sd-primary)] hover:bg-[var(--sd-primary-hover)] text-white text-xs font-semibold shadow-md transition cursor-pointer flex-shrink-0"
                >
                  {tokenLoading ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <KeyRound className="w-4 h-4 text-[var(--sd-wheat)]" />
                  )}
                  <span>{tokenLoading ? "Issuing Token..." : "Generate Token (1-Click)"}</span>
                </button>
              </div>

              {/* Generator Configuration Options */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-[var(--sd-wheat)] uppercase tracking-wider">
                    Deployment Label (Optional)
                  </label>
                  <input
                    type="text"
                    value={tokenLabel}
                    onChange={(e) => setTokenLabel(e.target.value)}
                    placeholder="e.g. AWS Production EKS Nodes, Office Workstations"
                    className="w-full px-3.5 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs text-[var(--sd-text)] placeholder-[var(--sd-text-dim)] focus:outline-hidden focus:border-[var(--sd-border-strong)] transition"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-[var(--sd-wheat)] uppercase tracking-wider">
                    Token Expiration Window
                  </label>
                  <select
                    value={tokenExpiryHours}
                    onChange={(e) => setTokenExpiryHours(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-border-strong)] transition"
                  >
                    <option value="24">24 Hours (Standard Security)</option>
                    <option value="168">7 Days (Batch Fleet Deployment)</option>
                    <option value="720">30 Days (CI/CD Golden Image Baking)</option>
                  </select>
                </div>
              </div>

              {tokenError && (
                <div className="p-3.5 rounded-xl border border-red-500/40 bg-red-950/20 text-red-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span>{tokenError}</span>
                </div>
              )}

              {/* Generated Token Result Showcase */}
              {generatedResult && (
                <div className="p-6 rounded-2xl border border-emerald-500/40 bg-emerald-950/20 space-y-5 animate-in fade-in duration-200">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-emerald-500/20">
                    <div className="flex items-center gap-2 text-xs font-mono text-emerald-300">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Token Active &amp; Ready for Deployment</span>
                    </div>
                    <span className="text-[11px] font-mono text-[var(--sd-text-dim)]">
                      Expires: {new Date(generatedResult.expiresAt).toLocaleString()}
                    </span>
                  </div>

                  {/* Raw Secret Bar */}
                  <div className="p-3.5 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] flex items-center justify-between gap-3 font-mono text-xs">
                    <div className="truncate text-emerald-300 font-semibold selection:bg-[var(--sd-primary)]">
                      {generatedResult.token}
                    </div>
                    <button
                      onClick={() => copyToClipboard(generatedResult.token, "raw-token")}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-wheat)] transition cursor-pointer flex-shrink-0"
                    >
                      {copiedKey === "raw-token" ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Token</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Pre-formatted Installation Commands */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-[var(--sd-wheat)] uppercase tracking-wider">
                        Ready-to-Run Host Installer Commands:
                      </span>
                      <div className="flex items-center gap-1 p-0.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border-subtle)] text-[11px] font-mono">
                        <button
                          onClick={() => setAgentInstallTab("linux")}
                          className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                            agentInstallTab === "linux"
                              ? "bg-[var(--sd-panel-hover)] text-white font-semibold"
                              : "text-[var(--sd-text-dim)] hover:text-white"
                          }`}
                        >
                          Linux / macOS
                        </button>
                        <button
                          onClick={() => setAgentInstallTab("powershell")}
                          className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                            agentInstallTab === "powershell"
                              ? "bg-[var(--sd-panel-hover)] text-white font-semibold"
                              : "text-[var(--sd-text-dim)] hover:text-white"
                          }`}
                        >
                          Windows PowerShell
                        </button>
                        <button
                          onClick={() => setAgentInstallTab("msi")}
                          className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                            agentInstallTab === "msi"
                              ? "bg-[var(--sd-panel-hover)] text-white font-semibold"
                              : "text-[var(--sd-text-dim)] hover:text-white"
                          }`}
                        >
                          Windows MSI
                        </button>
                      </div>
                    </div>

                    <div className="relative rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] p-4 overflow-x-auto">
                      <pre className="font-mono text-xs text-[var(--sd-sand)] leading-relaxed whitespace-pre-wrap">
                        <code>
                          {agentInstallTab === "linux" && generatedResult.installCommands.linux}
                          {agentInstallTab === "powershell" && generatedResult.installCommands.powershell}
                          {agentInstallTab === "msi" && generatedResult.installCommands.msi}
                        </code>
                      </pre>
                      <button
                        onClick={() => {
                          const cmd =
                            agentInstallTab === "linux"
                              ? generatedResult.installCommands.linux
                              : agentInstallTab === "powershell"
                              ? generatedResult.installCommands.powershell
                              : generatedResult.installCommands.msi;
                          copyToClipboard(cmd, "install-cmd");
                        }}
                        className="absolute top-3 right-3 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-surface)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-wheat)] transition cursor-pointer shadow-xs"
                      >
                        {copiedKey === "install-cmd" ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400">Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Command</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Active & Historical Enrollment Tokens Table */}
            <div className="p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[var(--sd-border-subtle)]">
                <div>
                  <h3 className="text-base font-bold text-[var(--sd-sand)]">
                    Active Tenant Enrollment Tokens
                  </h3>
                  <p className="text-xs text-[var(--sd-text-dim)] mt-0.5">
                    Authorized tokens tracked in cryptographic Merkle audit ledger for tenant {activeUser.tenantName}.
                  </p>
                </div>
                <button
                  onClick={fetchTokens}
                  className="p-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-dim)] hover:text-white transition cursor-pointer"
                  title="Refresh Token Ledger"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>

              {tokensList.length === 0 ? (
                <div className="text-center py-12 text-xs font-mono text-[var(--sd-text-dim)]">
                  No active enrollment tokens. Click &quot;Generate Token (1-Click)&quot; above to connect your first server.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[var(--sd-border)] text-xs font-mono uppercase text-[var(--sd-wheat)]">
                        <th className="py-3 px-3">Token ID / Label</th>
                        <th className="py-3 px-3">Status</th>
                        <th className="py-3 px-3">Usage</th>
                        <th className="py-3 px-3">Expires At</th>
                        <th className="py-3 px-3">Created By</th>
                        <th className="py-3 px-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--sd-border-subtle)] font-mono">
                      {tokensList.map((tok) => {
                        const isExpired = new Date(tok.expires_at).getTime() < Date.now();
                        const isRevoked = Boolean(tok.revoked_at);
                        const isExhausted = tok.used_count >= tok.max_uses;
                        const isValid = !isExpired && !isRevoked && !isExhausted;

                        return (
                          <tr key={tok.id} className="hover:bg-[var(--sd-panel-hover)]/30 transition">
                            <td className="py-3 px-3 font-sans">
                              <div className="font-semibold text-[var(--sd-sand)]">
                                {tok.label || "Endpoint Enrollment Token"}
                              </div>
                              <div className="font-mono text-[11px] text-[var(--sd-text-dim)] truncate max-w-xs">
                                {tok.id}
                              </div>
                            </td>
                            <td className="py-3 px-3">
                              {isValid ? (
                                <span className="px-2 py-0.5 rounded-full text-[10px] bg-emerald-950/40 border border-emerald-500/40 text-emerald-400">
                                  Active
                                </span>
                              ) : isRevoked ? (
                                <span className="px-2 py-0.5 rounded-full text-[10px] bg-red-950/40 border border-red-500/40 text-red-400">
                                  Revoked
                                </span>
                              ) : isExhausted ? (
                                <span className="px-2 py-0.5 rounded-full text-[10px] bg-amber-950/40 border border-amber-500/40 text-amber-400">
                                  Enrolled
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded-full text-[10px] bg-zinc-800 border border-zinc-700 text-zinc-400">
                                  Expired
                                </span>
                              )}
                            </td>
                            <td className="py-3 px-3">
                              {tok.used_count} / {tok.max_uses}
                            </td>
                            <td className="py-3 px-3 text-[var(--sd-text-muted)]">
                              {new Date(tok.expires_at).toLocaleString()}
                            </td>
                            <td className="py-3 px-3 text-[var(--sd-text-dim)] truncate max-w-[120px]">
                              {tok.created_by}
                            </td>
                            <td className="py-3 px-3 text-right">
                              {isValid && (
                                <button
                                  onClick={() => handleRevokeToken(tok.id)}
                                  className="text-red-400 hover:text-red-300 hover:underline transition cursor-pointer inline-flex items-center gap-1"
                                  title="Revoke Token"
                                >
                                  <Trash2 className="w-3 h-3" />
                                  <span>Revoke</span>
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ─────────────────────────────────────────────────────────────────── */}
        {/* TAB 2: External Intel Keys (Shodan & HIBP) */}
        {/* ─────────────────────────────────────────────────────────────────── */}
        {activeTab === "third-party-keys" && (
          <div className="space-y-8">
            {/* RBAC Notice if caller is non-admin */}
            {!isAdmin && (
              <div className="p-4 rounded-2xl border border-amber-500/30 bg-amber-950/20 text-amber-300 text-xs flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="font-semibold text-amber-200 flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5" />
                    <span>Administrator Privileges Required (RBAC Enforced)</span>
                  </div>
                  <p className="text-[var(--sd-text-muted)] leading-relaxed">
                    External threat intelligence keys (Shodan &amp; HaveIBeenPwned) can only be added, updated, or removed by operators with <strong>System Admin</strong> or <strong>Super Admin</strong> authority. Your current role is <span className="font-mono text-amber-300 font-semibold">{activeUser.label || activeUser.role}</span> (Read-Only status view).
                  </p>
                </div>
              </div>
            )}

            {/* Shodan Configuration Card */}
            <div className="p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[var(--sd-border-subtle)]">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-2xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-red-400">
                    <Globe className="w-6 h-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-bold text-[var(--sd-sand)]">
                        Shodan External Attack Surface Intelligence
                      </h3>
                      {keysStatus?.shodan.configured ? (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950/40 border border-emerald-500/40 text-emerald-400">
                          Active &amp; Connected
                        </span>
                      ) : (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-zinc-800 border border-zinc-700 text-zinc-400">
                          Not Configured (Optional)
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                      Powers perimeter scanning, public open ports discovery, and CVE correlation for enterprise IP ranges.
                    </p>
                  </div>
                </div>

                {keysStatus?.shodan.apiInfo && (
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border-subtle)] text-xs font-mono text-[var(--sd-wheat)]">
                    <span>Plan: {keysStatus.shodan.apiInfo.plan || "Community"}</span>
                    <span>•</span>
                    <span>Credits: {keysStatus.shodan.apiInfo.queryCredits ?? 0}</span>
                  </div>
                )}
              </div>

              {/* Shodan Input Form */}
              <div className="space-y-3">
                <label className="text-xs font-mono text-[var(--sd-wheat)] uppercase tracking-wider flex items-center justify-between">
                  <span>SHODAN API KEY</span>
                  <a
                    href="https://account.shodan.io"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[var(--sd-text-dim)] hover:text-[var(--sd-wheat)] transition inline-flex items-center gap-1 normal-case"
                  >
                    <span>Get Key from Shodan</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </label>

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      type={showShodanKey ? "text" : "password"}
                      value={shodanInput}
                      onChange={(e) => setShodanInput(e.target.value)}
                      disabled={!isAdmin}
                      placeholder={
                        !isAdmin
                          ? keysStatus?.shodan.maskedKey
                            ? `Configured: ${keysStatus.shodan.maskedKey} (Admin required to modify)`
                            : "Administrator privileges required to add key"
                          : keysStatus?.shodan.maskedKey
                          ? `Currently configured: ${keysStatus.shodan.maskedKey}`
                          : "Paste your Shodan API key..."
                      }
                      className="w-full pl-3.5 pr-10 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs font-mono text-[var(--sd-text)] placeholder-[var(--sd-text-dim)] focus:outline-hidden focus:border-[var(--sd-border-strong)] transition disabled:opacity-60 disabled:cursor-not-allowed"
                    />
                    <button
                      type="button"
                      onClick={() => setShowShodanKey(!showShodanKey)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--sd-text-dim)] hover:text-white"
                      tabIndex={-1}
                    >
                      {showShodanKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleSaveShodan(true)}
                      disabled={!isAdmin || shodanTesting || (!shodanInput.trim() && !keysStatus?.shodan.configured)}
                      className="sd-button px-3.5 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-wheat)] transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                    >
                      {!isAdmin && <Lock className="w-3 h-3 text-[var(--sd-text-dim)]" />}
                      <span>{shodanTesting ? "Testing..." : "Test Connection"}</span>
                    </button>

                    <button
                      onClick={() => handleSaveShodan(false)}
                      disabled={!isAdmin || shodanTesting || !shodanInput.trim()}
                      className="sd-button px-4 py-2.5 rounded-xl bg-[var(--sd-primary)] hover:bg-[var(--sd-primary-hover)] text-white text-xs font-semibold shadow-xs transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                    >
                      {!isAdmin && <Lock className="w-3 h-3" />}
                      <span>Save Key</span>
                    </button>

                    {keysStatus?.shodan.configured && (
                      <button
                        onClick={handleRemoveShodan}
                        disabled={!isAdmin}
                        className="p-2.5 rounded-xl border border-red-500/30 hover:bg-red-950/30 text-red-400 transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        title={isAdmin ? "Remove Key" : "Admin privileges required to remove key"}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>

                {shodanFeedback && (
                  <div
                    className={`p-3 rounded-xl text-xs flex items-center gap-2 ${
                      shodanFeedback.type === "success"
                        ? "bg-emerald-950/30 border border-emerald-500/40 text-emerald-300"
                        : "bg-red-950/30 border border-red-500/40 text-red-300"
                    }`}
                  >
                    {shodanFeedback.type === "success" ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
                    )}
                    <span>{shodanFeedback.message}</span>
                  </div>
                )}
              </div>
            </div>

            {/* HaveIBeenPwned (HIBP) Configuration Card */}
            <div className="p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[var(--sd-border-subtle)]">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-2xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-cyan-400">
                    <Database className="w-6 h-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-bold text-[var(--sd-sand)]">
                        HaveIBeenPwned (HIBP) Domain Breach Monitoring
                      </h3>
                      {keysStatus?.hibp.configured ? (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950/40 border border-emerald-500/40 text-emerald-400">
                          Active &amp; Connected
                        </span>
                      ) : (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-zinc-800 border border-zinc-700 text-zinc-400">
                          Not Configured (Optional)
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                      Monitors corporate email domains for compromised credentials in publicly dumped breach databases.
                    </p>
                  </div>
                </div>
              </div>

              {/* HIBP Input Form */}
              <div className="space-y-3">
                <label className="text-xs font-mono text-[var(--sd-wheat)] uppercase tracking-wider flex items-center justify-between">
                  <span>HIBP API KEY</span>
                  <a
                    href="https://haveibeenpwned.com/API/Key"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[var(--sd-text-dim)] hover:text-[var(--sd-wheat)] transition inline-flex items-center gap-1 normal-case"
                  >
                    <span>Get Key from HaveIBeenPwned</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </label>

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      type={showHibpKey ? "text" : "password"}
                      value={hibpInput}
                      onChange={(e) => setHibpInput(e.target.value)}
                      disabled={!isAdmin}
                      placeholder={
                        !isAdmin
                          ? keysStatus?.hibp.maskedKey
                            ? `Configured: ${keysStatus.hibp.maskedKey} (Admin required to modify)`
                            : "Administrator privileges required to add key"
                          : keysStatus?.hibp.maskedKey
                          ? `Currently configured: ${keysStatus.hibp.maskedKey}`
                          : "Paste your HaveIBeenPwned API key..."
                      }
                      className="w-full pl-3.5 pr-10 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs font-mono text-[var(--sd-text)] placeholder-[var(--sd-text-dim)] focus:outline-hidden focus:border-[var(--sd-border-strong)] transition disabled:opacity-60 disabled:cursor-not-allowed"
                    />
                    <button
                      type="button"
                      onClick={() => setShowHibpKey(!showHibpKey)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--sd-text-dim)] hover:text-white"
                      tabIndex={-1}
                    >
                      {showHibpKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleSaveHibp(true)}
                      disabled={!isAdmin || hibpTesting || (!hibpInput.trim() && !keysStatus?.hibp.configured)}
                      className="sd-button px-3.5 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-wheat)] transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                    >
                      {!isAdmin && <Lock className="w-3 h-3 text-[var(--sd-text-dim)]" />}
                      <span>{hibpTesting ? "Testing..." : "Test Format"}</span>
                    </button>

                    <button
                      onClick={() => handleSaveHibp(false)}
                      disabled={!isAdmin || hibpTesting || !hibpInput.trim()}
                      className="sd-button px-4 py-2.5 rounded-xl bg-[var(--sd-primary)] hover:bg-[var(--sd-primary-hover)] text-white text-xs font-semibold shadow-xs transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                    >
                      {!isAdmin && <Lock className="w-3 h-3" />}
                      <span>Save Key</span>
                    </button>

                    {keysStatus?.hibp.configured && (
                      <button
                        onClick={handleRemoveHibp}
                        disabled={!isAdmin}
                        className="p-2.5 rounded-xl border border-red-500/30 hover:bg-red-950/30 text-red-400 transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        title={isAdmin ? "Remove Key" : "Admin privileges required to remove key"}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>

                {hibpFeedback && (
                  <div
                    className={`p-3 rounded-xl text-xs flex items-center gap-2 ${
                      hibpFeedback.type === "success"
                        ? "bg-emerald-950/30 border border-emerald-500/40 text-emerald-300"
                        : "bg-red-950/30 border border-red-500/40 text-red-300"
                    }`}
                  >
                    {hibpFeedback.type === "success" ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
                    )}
                    <span>{hibpFeedback.message}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Telemetry Ingest Key Box */}
            {keysStatus?.ingest && (
              <div className="p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md space-y-4">
                <div className="flex items-center gap-3 pb-3 border-b border-[var(--sd-border-subtle)]">
                  <div className="p-2 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-purple-400">
                    <Radio className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-base font-bold text-[var(--sd-sand)]">
                      Tenant Telemetry Ingest Key (Syslog / SIEM / Webhooks)
                    </h4>
                    <p className="text-xs text-[var(--sd-text-muted)]">
                      Send syslog-ng, Wazuh alerts, or Cloudflare logs into your ShieldDesk pipeline.
                    </p>
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-3 font-mono text-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="text-[var(--sd-text-dim)]">Ingest Endpoint:</span>
                    <span className="text-[var(--sd-wheat)]">{keysStatus.ingest.endpoint}</span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="text-[var(--sd-text-dim)]">Header:</span>
                    <span className="text-[var(--sd-sand)]">
                      X-ShieldDesk-Ingest-Key: {keysStatus.ingest.key}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
