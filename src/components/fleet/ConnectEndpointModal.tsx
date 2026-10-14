"use client";

import React, { useState, useEffect, useId } from "react";
import {
  Plug,
  X,
  Key,
  Copy,
  ClipboardCheck,
  CheckCircle2,
  AlertTriangle,
  Server,
  Terminal,
  ShieldCheck,
  Activity,
  Cpu,
  Radio,
  RefreshCw,
  HardDrive,
  ArrowLeft,
  Edit3,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { EndpointAgentRecord } from "@/lib/fleet/fleet";

export interface ConnectEndpointModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeUserId: string;
  serverUrl?: string;
  existingAgents?: EndpointAgentRecord[];
  onEndpointConnected?: () => void;
}

interface EnrollResult {
  token: string;
  tokenId: string;
  expiresAt: string;
  tenantId: string;
  installCommands?: {
    linux?: string;
    powershell?: string;
    msi?: string;
  };
}

type TargetOS = "windows" | "linux" | "darwin" | "nodejs";
type AgentRuntime = "go-binary" | "script" | "nodejs";

export function ConnectEndpointModal({
  isOpen,
  onClose,
  activeUserId,
  serverUrl,
  existingAgents = [],
  onEndpointConnected,
}: ConnectEndpointModalProps) {
  const titleId = useId();

  // Configuration state
  const [targetOs, setTargetOs] = useState<TargetOS>("windows");
  const [runtimeType, setRuntimeType] = useState<AgentRuntime>("go-binary");
  const [hostName, setHostName] = useState("");
  const [expiryHours, setExpiryHours] = useState("24");

  // Enrollment request & result state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EnrollResult | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Initial count of agents to detect newly connected agents
  const [initialAgentIds, setInitialAgentIds] = useState<Set<string>>(new Set());
  const [newlyConnectedAgent, setNewlyConnectedAgent] = useState<EndpointAgentRecord | null>(null);

  // Sync initial agents when modal opens
  useEffect(() => {
    if (isOpen) {
      setInitialAgentIds(new Set(existingAgents.map((a) => a.id)));
      setNewlyConnectedAgent(null);
      setError(null);
    } else {
      // Reset result state when closed
      setResult(null);
      setError(null);
      setNewlyConnectedAgent(null);
    }
  }, [isOpen]); // eslint-disable-line react-hooks/exhaustive-deps

  // Detect new agent arriving via live props
  useEffect(() => {
    if (!isOpen || !result) return;
    const freshAgent = existingAgents.find((a) => !initialAgentIds.has(a.id));
    if (freshAgent) {
      setNewlyConnectedAgent(freshAgent);
      onEndpointConnected?.();
    }
  }, [existingAgents, isOpen, result, initialAgentIds, onEndpointConnected]);

  // Handle ESC key and backdrop lock
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      document.addEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const controlPlaneUrl =
    serverUrl ||
    (typeof window !== "undefined" ? window.location.origin : "http://localhost:3000");

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // fallback
    }
  };

  const handleGenerateToken = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    const cleanHost = hostName.trim();
    const tokenLabel = cleanHost || `Agent-${targetOs.toUpperCase()}-${new Date().toISOString().slice(0, 10)}`;

    try {
      const res = await fetch("/api/fleet/enrollment-tokens", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          label: tokenLabel,
          expiresInHours: Number(expiryHours) || 24,
          maxUses: 1,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        setResult({
          token: data.token,
          tokenId: data.tokenId || "",
          expiresAt: data.expiresAt,
          tenantId: data.tenantId || "mints-global",
          installCommands: data.installCommands,
        });
      } else {
        setError(data.error || "Failed to generate enrollment token");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Network error generating token");
    } finally {
      setLoading(false);
    }
  };

  // Generate dynamic run commands based on selected OS, runtime, and custom host identifier
  const getCommand = () => {
    if (!result) return "";
    const token = result.token;
    const cleanHost = hostName.trim();

    if (runtimeType === "nodejs" || targetOs === "nodejs") {
      const hostFlag = cleanHost ? ` --hostname "${cleanHost}"` : "";
      return `node agent/agent-daemon.js --token ${token} --control-url ${controlPlaneUrl}${hostFlag}`;
    }

    if (runtimeType === "script") {
      if (targetOs === "windows") {
        const hostFlag = cleanHost ? ` -Hostname "${cleanHost}"` : "";
        return `powershell -ExecutionPolicy Bypass -File .\\agent\\deploy-agent.ps1 -Token "${token}" -ControlPlaneUrl "${controlPlaneUrl}"${hostFlag}`;
      }
      const hostParam = cleanHost || "$(hostname)";
      return `chmod +x ./agent/deploy-agent.sh && ./agent/deploy-agent.sh "${controlPlaneUrl}" "${result.tenantId}" "${hostParam}"`;
    }

    // Native Go binary
    const hostFlag = cleanHost ? ` -hostname "${cleanHost}"` : "";
    switch (targetOs) {
      case "windows":
        return `.\\shielddesk-agent.exe -token ${token} -control-url ${controlPlaneUrl}${hostFlag}`;
      case "linux":
        return `./shielddesk-agent -token ${token} -control-url ${controlPlaneUrl}${hostFlag}`;
      case "darwin":
        return `./shielddesk-agent -token ${token} -control-url ${controlPlaneUrl}${hostFlag}`;
      default:
        return `.\\shielddesk-agent.exe -token ${token} -control-url ${controlPlaneUrl}${hostFlag}`;
    }
  };

  const currentCommand = getCommand();

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-3 sm:p-5 overflow-y-auto"
    >
      <div className="sd-surface border border-[var(--sd-border)] rounded-2xl w-full max-w-3xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden bg-[var(--sd-surface)] text-[var(--sd-text)] animate-in fade-in-50 zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4.5 border-b border-[var(--sd-border)] bg-[var(--sd-bg)]">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-[var(--sd-pine)]/15 border border-[var(--sd-pine)]/30 text-[var(--sd-pine)] flex items-center justify-center shadow-xs">
              <Plug className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 id={titleId} className="text-base font-semibold text-[var(--sd-text)] tracking-tight">
                  Connect a Real Endpoint
                </h2>
                <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-[var(--sd-pine)]/10 text-[var(--sd-pine)] border border-[var(--sd-pine)]/20 font-medium">
                  Fleet Agent PKI
                </span>
              </div>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                Enroll a physical or virtual machine to stream authentic telemetry &amp; execute governed actions
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
            title="Close modal (Esc)"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* 1. Inquiry Card: Explains what connecting a real endpoint is and asks user confirmation */}
          <div className="rounded-xl border border-[var(--sd-pine)]/30 bg-[var(--sd-pine)]/5 p-4.5 space-y-3">
            <div className="flex items-start gap-3">
              <div className="h-8 w-8 rounded-lg bg-[var(--sd-pine)]/20 border border-[var(--sd-pine)]/40 text-[var(--sd-pine)] flex items-center justify-center shrink-0 mt-0.5">
                <Server className="h-4 w-4" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-medium text-[var(--sd-text)]">
                  Connect a Real Endpoint Host
                </h3>
                <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
                  Would you like to enroll a genuine machine into the ShieldDesk SOC fleet? Installing the
                  ShieldDesk Universal Endpoint Agent on a target host allows it to stream live hardware telemetry,
                  report active processes, take pre-flight safety snapshots, and execute authorized containment actions.
                </p>
              </div>
            </div>

            {/* Core Capability Badges */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-[var(--sd-pine)]/20 text-[11px] font-mono text-[var(--sd-text-muted)]">
              <div className="flex items-center gap-1.5">
                <Activity className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span>Live EPS &amp; Vitals</span>
              </div>
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-[var(--sd-pine)] shrink-0" />
                <span>Signed Commands</span>
              </div>
              <div className="flex items-center gap-1.5">
                <HardDrive className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                <span>Pre-Flight Snapshots</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Cpu className="h-3.5 w-3.5 text-blue-400 shrink-0" />
                <span>10k Ring Buffer</span>
              </div>
            </div>
          </div>

          {!result ? (
            /* Stage 1: Questions & Configuration before token generation */
            <form onSubmit={handleGenerateToken} className="space-y-5">
              {/* Host Identifier & Token Expiration */}
              <div className="space-y-2">
                <label className="text-xs font-semibold text-[var(--sd-text)] uppercase tracking-wider font-mono">
                  Endpoint Host Configuration &amp; Security Window
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2 space-y-1">
                    <div className="flex items-center justify-between">
                      <label className="text-[11px] font-medium text-[var(--sd-text-muted)] block">
                        Host Friendly Name / Identifier (optional)
                      </label>
                      <span className="text-[10px] text-[var(--sd-pine)] font-mono">
                        Editable anytime
                      </span>
                    </div>
                    <input
                      type="text"
                      placeholder="e.g. Workstation-CEO, SecOps-Prod-01, Ubuntu-Server"
                      value={hostName}
                      onChange={(e) => setHostName(e.target.value)}
                      className="sd-input w-full bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-medium text-[var(--sd-text-muted)] block">
                      Token Validity Window
                    </label>
                    <select
                      value={expiryHours}
                      onChange={(e) => setExpiryHours(e.target.value)}
                      className="sd-input w-full bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-xs text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    >
                      <option value="1">1 hour (Strict)</option>
                      <option value="6">6 hours</option>
                      <option value="24">24 hours (Recommended)</option>
                      <option value="72">72 hours</option>
                      <option value="168">7 days (Batch fleet)</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Error feedback */}
              {error && (
                <div className="flex items-center gap-2 text-red-400 text-xs font-mono bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {/* Modal Footer Actions */}
              <div className="flex items-center justify-between pt-3 border-t border-[var(--sd-border)]">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  disabled={loading}
                  className="sd-button sd-button-primary px-5 py-2.5 rounded-xl text-xs font-medium flex items-center gap-2 cursor-pointer shadow-xs disabled:opacity-50"
                >
                  <Key className="h-3.5 w-3.5" />
                  <span>{loading ? "Generating Enrollment Token..." : "Generate Token & Connect Real Endpoint"}</span>
                </button>
              </div>
            </form>
          ) : (
            /* Stage 2: Token generated — user can change host, switch OS, and copy updated commands */
            <div className="space-y-5">
              {/* Token Generated Success Banner with Change Host Back button */}
              <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
                <div className="flex items-center gap-2.5">
                  <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                  <div>
                    <span className="text-xs font-medium text-emerald-300">
                      Enrollment Token Generated Successfully
                    </span>
                    <p className="text-[11px] text-emerald-400/80 font-mono">
                      Expires {new Date(result.expiresAt).toLocaleString()} • Tenant: {result.tenantId}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setResult(null);
                      setNewlyConnectedAgent(null);
                    }}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] font-mono transition cursor-pointer"
                    title="Return to initial configuration to change OS, runtime mode, or expiry"
                  >
                    <ArrowLeft className="h-3 w-3 text-[var(--sd-pine)]" />
                    <span>Change Host Settings</span>
                  </button>

                  <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    Ready to Connect
                  </span>
                </div>
              </div>

              {/* Live Handshake Detector Beacon */}
              <div className={cn(
                "p-3.5 rounded-xl border transition flex items-center justify-between",
                newlyConnectedAgent
                  ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
                  : "bg-[var(--sd-bg)] border-[var(--sd-border)]"
              )}>
                <div className="flex items-center gap-3">
                  <div className="relative flex h-3 w-3">
                    {newlyConnectedAgent ? (
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                    ) : (
                      <>
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--sd-pine)] opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-3 w-3 bg-[var(--sd-pine)]"></span>
                      </>
                    )}
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-[var(--sd-text)]">
                      {newlyConnectedAgent
                        ? `Endpoint Handshake Verified: ${newlyConnectedAgent.hostname}`
                        : "Listening for Endpoint Connection..."}
                    </p>
                    <p className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                      {newlyConnectedAgent
                        ? `Status: Connected • ${newlyConnectedAgent.os_type} • Telemetry Streaming Live`
                        : "Run the command below on your endpoint host. The dashboard will automatically detect the connection."}
                    </p>
                  </div>
                </div>

                {!newlyConnectedAgent && (
                  <span className="flex items-center gap-1.5 text-[11px] font-mono text-[var(--sd-pine)]">
                    <Radio className="h-3 w-3 animate-pulse" />
                    <span>Listening</span>
                  </span>
                )}
              </div>

              {/* ── Active Host Configuration / Editable Host Identifier ── */}
              <div className="rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-pine)]/40 p-4 space-y-2.5 shadow-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Edit3 className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                    <span className="text-xs font-semibold text-[var(--sd-text)] uppercase tracking-wider font-mono">
                      Target Host Machine Name:
                    </span>
                  </div>
                  <span className="text-[10px] text-[var(--sd-pine)] font-mono bg-[var(--sd-pine)]/10 px-2 py-0.5 rounded border border-[var(--sd-pine)]/20">
                    Live editable — updates command below
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2.5">
                  <div className="flex-1 min-w-[220px]">
                    <input
                      type="text"
                      placeholder="e.g. Workstation-CEO, SecOps-Prod-01, Ubuntu-Server (or leave blank to auto-detect)"
                      value={hostName}
                      onChange={(e) => setHostName(e.target.value)}
                      className="sd-input w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    />
                  </div>

                  {hostName.trim() ? (
                    <button
                      type="button"
                      onClick={() => setHostName("")}
                      className="px-2.5 py-2 rounded-xl border border-[var(--sd-border)] text-[11px] font-mono text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                      title="Clear custom host name to auto-detect target machine name"
                    >
                      Clear / Auto-Detect
                    </button>
                  ) : (
                    <span className="text-[11px] font-mono text-[var(--sd-text-muted)] px-1">
                      (Auto-detects computer name)
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-[var(--sd-text-muted)] font-mono">
                  You can change the target host at any time above. If you want to change the OS, runtime mode, or expiry time, click{" "}
                  <button
                    type="button"
                    onClick={() => {
                      setResult(null);
                      setNewlyConnectedAgent(null);
                    }}
                    className="text-[var(--sd-pine)] underline hover:opacity-80 cursor-pointer"
                  >
                    Change Host Settings
                  </button>.
                </p>
              </div>

              {/* Token Display Box */}
              <div className="rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase tracking-wider">
                    One-Time Cryptographic Enrollment Token
                  </span>
                  <span className="text-[10px] text-amber-400 font-mono">
                    Shown once for security
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-xs font-mono text-[var(--sd-pine)] bg-[var(--sd-panel-raised)] px-3 py-2 rounded-lg border border-[var(--sd-border)] break-all select-all font-semibold">
                    {result.token}
                  </code>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(result.token, "token")}
                    className="p-2 rounded-lg hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] transition cursor-pointer text-[var(--sd-text)]"
                    title="Copy token"
                  >
                    {copiedKey === "token" ? (
                      <ClipboardCheck className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <Copy className="h-4 w-4 text-[var(--sd-text-muted)]" />
                    )}
                  </button>
                </div>
              </div>

              {/* OS & Runtime Switcher in Stage 2 so user can switch target platform seamlessly */}
              <div className="space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-[var(--sd-text)] uppercase tracking-wider font-mono">
                    Run on Target Endpoint Host:
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {/* OS selector tabs */}
                    <div className="flex items-center gap-0.5 bg-[var(--sd-bg)] p-0.5 rounded-lg border border-[var(--sd-border)]">
                      <button
                        type="button"
                        onClick={() => setTargetOs("windows")}
                        className={cn(
                          "px-2.5 py-1 rounded text-[11px] font-medium font-mono transition cursor-pointer",
                          targetOs === "windows"
                            ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)]"
                            : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                        )}
                      >
                        Windows
                      </button>
                      <button
                        type="button"
                        onClick={() => setTargetOs("linux")}
                        className={cn(
                          "px-2.5 py-1 rounded text-[11px] font-medium font-mono transition cursor-pointer",
                          targetOs === "linux"
                            ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)]"
                            : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                        )}
                      >
                        Linux
                      </button>
                      <button
                        type="button"
                        onClick={() => setTargetOs("darwin")}
                        className={cn(
                          "px-2.5 py-1 rounded text-[11px] font-medium font-mono transition cursor-pointer",
                          targetOs === "darwin"
                            ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)]"
                            : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                        )}
                      >
                        macOS
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setTargetOs("nodejs");
                          setRuntimeType("nodejs");
                        }}
                        className={cn(
                          "px-2.5 py-1 rounded text-[11px] font-medium font-mono transition cursor-pointer",
                          targetOs === "nodejs"
                            ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)]"
                            : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                        )}
                      >
                        Node.js
                      </button>
                    </div>

                    {/* Runtime mode toggle (for Windows / Linux) */}
                    {targetOs !== "nodejs" && (
                      <div className="flex items-center gap-0.5 bg-[var(--sd-bg)] p-0.5 rounded-lg border border-[var(--sd-border)]">
                        <button
                          type="button"
                          onClick={() => setRuntimeType("go-binary")}
                          className={cn(
                            "px-2 py-1 rounded text-[10px] font-mono transition cursor-pointer",
                            runtimeType === "go-binary"
                              ? "bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] font-semibold border border-[var(--sd-pine)]/30"
                              : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                          )}
                          title="Native Go compiled binary"
                        >
                          Binary
                        </button>
                        <button
                          type="button"
                          onClick={() => setRuntimeType("script")}
                          className={cn(
                            "px-2 py-1 rounded text-[10px] font-mono transition cursor-pointer",
                            runtimeType === "script"
                              ? "bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] font-semibold border border-[var(--sd-pine)]/30"
                              : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                          )}
                          title="Automated deploy script (PowerShell or Bash)"
                        >
                          1-Click Script
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Formatted Execution Snippet */}
                <div className="rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                      <span className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase tracking-wider font-semibold">
                        {targetOs === "windows"
                          ? runtimeType === "script"
                            ? "PowerShell Deploy Script (Windows)"
                            : "Native Binary (Command Prompt / PowerShell)"
                          : targetOs === "linux"
                          ? runtimeType === "script"
                            ? "Automated Systemd Deploy Script (Linux)"
                            : "Native Binary (Linux Server)"
                          : targetOs === "darwin"
                          ? "Terminal (macOS Host)"
                          : "Node.js Daemon (Cross-Platform)"}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-[var(--sd-pine)]">
                      Control Plane: {controlPlaneUrl}
                    </span>
                  </div>

                  <div className="flex items-start gap-2">
                    <code className="flex-1 text-[11px] font-mono text-emerald-300 bg-[var(--sd-panel-raised)] p-3 rounded-lg border border-[var(--sd-border)] break-all select-all whitespace-pre-wrap leading-relaxed">
                      {currentCommand}
                    </code>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(currentCommand, "cmd")}
                      className="p-2.5 rounded-lg hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] transition cursor-pointer text-[var(--sd-text)] mt-0.5"
                      title="Copy full command"
                    >
                      {copiedKey === "cmd" ? (
                        <ClipboardCheck className="h-4 w-4 text-emerald-400" />
                      ) : (
                        <Copy className="h-4 w-4 text-[var(--sd-text-muted)]" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Step-by-step guidance list */}
                <div className="text-[11px] text-[var(--sd-text-muted)] space-y-1.5 pl-1 pt-1 font-mono">
                  <div className="flex items-start gap-2">
                    <span className="text-[var(--sd-pine)] font-semibold">1.</span>
                    <span>Copy the command above or provide the enrollment token to your machine.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-[var(--sd-pine)] font-semibold">2.</span>
                    <span>Run in terminal on the endpoint machine (with admin/root privileges if configuring firewall).</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-[var(--sd-pine)] font-semibold">3.</span>
                    <span>The agent will register with the control plane and begin streaming live heartbeats and events immediately.</span>
                  </div>
                </div>
              </div>

              {/* Modal Footer Actions */}
              <div className="flex items-center justify-between pt-3 border-t border-[var(--sd-border)]">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setResult(null);
                      setNewlyConnectedAgent(null);
                    }}
                    className="px-3.5 py-2 rounded-xl text-xs font-mono text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer flex items-center gap-1.5 border border-[var(--sd-border)]"
                  >
                    <ArrowLeft className="h-3 w-3" />
                    <span>Change Host / Settings</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setResult(null);
                      setNewlyConnectedAgent(null);
                      handleGenerateToken();
                    }}
                    className="px-3.5 py-2 rounded-xl text-xs font-mono text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] transition cursor-pointer flex items-center gap-1.5"
                  >
                    <RefreshCw className="h-3 w-3" />
                    <span>Generate New Token</span>
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    onEndpointConnected?.();
                    onClose();
                  }}
                  className="sd-button sd-button-primary px-5 py-2.5 rounded-xl text-xs font-medium cursor-pointer shadow-xs"
                >
                  {newlyConnectedAgent ? "Done — View Enrolled Host" : "Done / Close Modal"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
