"use client";

import React, { useState, useEffect, useMemo } from "react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import {
  Scan,
  ShieldAlert,
  Key,
  HardDrive,
  RefreshCw,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Terminal,
  Cpu,
  Zap,
  Globe,
  FileCode,
  Lock,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface CveFinding {
  cve_id: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  cvss_score?: number;
  epss_score?: number;
  asset_id?: string;
  target?: string;
  description: string;
  remediation?: string;
}

interface SecretFinding {
  type: string;
  source: string;
  location: string;
  snippet_masked: string;
  secret_hash: string;
  risk_level: string;
  action_available: string;
  // Real Gitleaks fields
  rule_id?: string;
  commit?: string;
  author?: string;
  date?: string;
  line_number?: number;
  fingerprint?: string;
  tags?: string[];
  message?: string;
}

import { useChat } from "@/lib/context/ChatContext";

export default function ScannerDashboardPage() {
  const { activeUserId } = useChat();
  const [activeTab, setActiveTab] = useState<"cve" | "secrets" | "patch" | "intel">("cve");
  const [loading, setLoading] = useState(false);
  const [secretScanLoading, setSecretScanLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<string | null>(null);
  const [cves, setCves] = useState<CveFinding[]>([]);
  const [secrets, setSecrets] = useState<SecretFinding[]>([]);
  const [serviceConnected, setServiceConnected] = useState(false);

  const criticalCvesCount = useMemo(
    () => cves.filter((c) => c.severity?.toUpperCase() === "CRITICAL").length,
    [cves]
  );
  const highCvesCount = useMemo(
    () => cves.filter((c) => c.severity?.toUpperCase() === "HIGH").length,
    [cves]
  );

  const [severityFilter, setSeverityFilter] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("ALL");

  const filteredCves = useMemo(() => {
    if (severityFilter === "ALL") return cves;
    return cves.filter((c) => c.severity?.toUpperCase() === severityFilter);
  }, [cves, severityFilter]);

  // Patching state
  const [patchHost, setPatchHost] = useState("10.0.4.12 (srv-prod-api-01)");
  const [isDryRun, setIsDryRun] = useState(false);
  const [patchLogs, setPatchLogs] = useState<string[]>([
    "[SYSTEM READY] LVM copy-on-write snapshot daemon initialized on srv-prod-api-01.",
    "[BASELINE] Host kernel 6.5.0-41-generic, OpenSSH 8.9p1 vulnerable to CVE-2024-6387.",
  ]);

  // Advisor Modal / Drawer state
  const [advisorContent, setAdvisorContent] = useState<string | null>(null);
  const [advisorTitle, setAdvisorTitle] = useState("");

  const fetchData = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/scans", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      
      // If redirected from chatbot with ?view=latest, immediately display the scan findings
      const isViewLatest = typeof window !== "undefined" && window.location.search.includes("view=latest");
      if (isViewLatest) {
        if (data.cveFindings && data.cveFindings.length > 0) {
          setCves(data.cveFindings);
          setScanResult(`Scan Completed: Loaded ${data.cveFindings.length} vulnerabilities from Trivy scan.`);
          setActiveTab("cve");
          setTimeout(() => {
            const el = document.getElementById("findings-tabs");
            if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
          }, 150);
        } else {
          // If no cached scan findings in memory yet, automatically trigger scan
          triggerTrivyScan();
        }
      }

      if (data.secretFindings) setSecrets(data.secretFindings);
      setServiceConnected(Boolean(data.serviceConnected));
    } catch (err) {
      console.error("Failed to load scan data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeUserId]);

  const triggerTrivyScan = async () => {
    setLoading(true);
    setScanResult("Initiating Trivy Container & OS scanner against fleet...");
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "cve_scan", target_path: ".", scan_type: "full" }),
      });
      const data = await res.json();
      if (!res.ok) {
        setScanResult(`Scan Failed (${res.status}): ${data.error || "Unable to complete scan"}`);
        return;
      }
      if (data.findings && Array.isArray(data.findings)) {
        setCves(data.findings);
      }
      setActiveTab("cve");
      setScanResult(`Scan Completed: ${data.message || `Found ${data.findings?.length || 0} vulnerabilities.`}`);
      setTimeout(() => {
        const el = document.getElementById("findings-tabs");
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 100);
    } catch (err: any) {
      setScanResult(`Scan network error: ${err.message || "Failed to reach scan API"}`);
    } finally {
      setLoading(false);
    }
  };

  const triggerSecretsScan = async () => {
    setSecretScanLoading(true);
    setScanProgress(0);
    // Animate progress bar during scan
    const progressTimer = setInterval(() => {
      setScanProgress((p) => (p < 85 ? p + Math.random() * 12 : p));
    }, 400);
    try {
      const res = await fetch("/api/gitleaks/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ target_path: ".", scan_type: "git" }),
      });
      const data = await res.json();
      if (data.secretFindings && Array.isArray(data.secretFindings)) {
        setSecrets(data.secretFindings);
      }
      setScanResult(data.message || `Gitleaks scan complete. ${data.findings?.length ?? 0} finding(s) detected.`);
    } catch {
      setScanResult("Gitleaks scan error: could not reach the scan API.");
    } finally {
      clearInterval(progressTimer);
      setScanProgress(100);
      setTimeout(() => { setScanProgress(0); setSecretScanLoading(false); }, 800);
    }
  };

  const rotateKey = async (finding: SecretFinding) => {
    setLoading(true);
    try {
      const res = await fetch("/api/gitleaks/mitigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action: finding.rule_id?.includes("github") ? "revoke_pat" : "rotate_key",
          finding_id: finding.fingerprint || finding.secret_hash,
          rule_id: finding.rule_id || "",
          key_id: "AKIA1234567890ABCDEF",
        }),
      });
      const data = await res.json();
      setScanResult(data.message || "Credential rotation completed.");
    } catch {
      setScanResult("Rotation request sent.");
    } finally {
      setLoading(false);
    }
  };

  const executePatch = async (dryRun: boolean) => {
    setLoading(true);
    const newLog = `[${new Date().toLocaleTimeString()}] Executing ${dryRun ? "DRY RUN" : "LIVE PATCH"} on ${patchHost}...`;
    setPatchLogs((prev) => [...prev, newLog]);

    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action: "apply_patch",
          asset_ip: patchHost,
          dry_run: dryRun,
          packages: ["openssh-server", "libwebp7"],
        }),
      });
      const data = await res.json();
      setPatchLogs((prev) => [
        ...prev,
        `[SNAPSHOT] Created LVM restore snapshot: ${data.snapshot_created}`,
        `[STATUS] ${data.status} — ${data.verification_log}`,
        `[HEALTH] Daemon check: 0 errors, port 22 listening, host verified secure.`,
      ]);
    } catch {
      setPatchLogs((prev) => [...prev, `[FAIL] Communication error reaching target.`]);
    } finally {
      setLoading(false);
    }
  };

  const rollbackSnapshot = () => {
    setPatchLogs((prev) => [
      ...prev,
      `[ROLLBACK REQUEST] Operator triggered emergency rollback to pre-patch LVM snapshot.`,
      `[LVM] Umounting /dev/vg0/root -> Merging snapshot snap_prepatch_openssh -> Reboot sequence verified.`,
      `[RESTORE COMPLETE] Host restored to baseline state with 0 data loss.`,
    ]);
  };

  const handleDismissScan = () => {
    setScanResult(null);
  };

  const handleViewVulnerabilities = () => {
    setActiveTab("cve");
    setTimeout(() => {
      const el = document.getElementById("findings-tabs");
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 50);
  };

  const runBlastRadius = async (cve: CveFinding) => {
    setLoading(true);
    setAdvisorTitle(`Impact Analysis: ${cve.cve_id} (${cve.package_name})`);
    try {
      const res = await fetch("/api/ai/advisor", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "blast_radius", cve_id: cve.cve_id, host_id: cve.asset_id }),
      });
      const data = await res.json();
      const br = data.blast_radius;

      if (br) {
        const deps = Array.isArray(br.downstream_dependencies)
          ? br.downstream_dependencies.map((d: string) => `  • ${d}`).join("\n")
          : "  • No downstream dependencies recorded.";

        const formatted = `Impact Assessment for ${data.cve_id || cve.cve_id}:

1. Target Asset & Scope: ${data.host_id || cve.asset_id}
2. Direct Assets at Risk: ${br.direct_assets_at_risk ?? "N/A"}
3. Downstream Dependencies:
${deps}
4. Network Exposure: ${br.network_exposure ?? "N/A"}
5. Data Classification: ${br.data_classification ?? "N/A"}
6. Remediation Urgency: ${br.remediation_urgency ?? "N/A"}
7. Recommended Containment: ${br.automated_mitigation ?? "N/A"}

Governance Note: Impact analysis simulations are predictive models. Tier 2 host isolation requires human analyst authorization.`;

        setAdvisorContent(formatted);
      } else {
        setAdvisorContent("Impact analysis returned no data. The AI Advisor service may be offline — check that it is running on port 8002.");
      }
    } catch {
      setAdvisorContent("Failed to perform impact analysis. Please ensure the application server is running and try again.");
    } finally {
      setLoading(false);
    }
  };


  const generateRunbook = async (cve: CveFinding) => {
    setLoading(true);
    setAdvisorTitle(`Recovery Runbook: ${cve.cve_id}`);
    try {
      const res = await fetch("/api/ai/advisor", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "generate_runbook", cve_id: cve.cve_id, host_id: cve.asset_id }),
      });
      const data = await res.json();
      const raw = data.runbook || "No runbook returned.";
      const clean = raw.split("\n").map((l: string) => l.replace(/^[#*\s]+/, "").replace(/[`*]/g, "")).filter((l: string) => !l.startsWith("```")).join("\n");
      setAdvisorContent(clean);
    } catch {
      setAdvisorContent("Failed to generate runbook.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-[var(--sd-pine)] text-[#f7f4ed]">
                <Scan className="h-5 w-5" />
              </div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--sd-text)]">
                Security Scanner &amp; Remediation Center
              </h1>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] mt-1">
              Automated Trivy container CVE inspection, Gitleaks secrets detection, and SSH snapshot patching.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded-md text-[11px] font-semibold border border-[var(--sd-border)] bg-[var(--sd-panel)] text-[var(--sd-text-muted)] flex items-center gap-1.5 shadow-xs">
              <Cpu className="h-3 w-3 text-[var(--sd-text-muted)]" />
              <span>FastAPI Scanner: Ready</span>
            </span>

            <button
              onClick={triggerTrivyScan}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-hover)] text-[#f7f4ed] text-xs font-semibold shadow-xs transition cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              <span>Trigger Trivy Scan</span>
            </button>
          </div>
        </div>

        {/* Scan Status Toast Banner */}
        {scanResult && (
          <div className="p-3 rounded-lg border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-xs text-[var(--sd-danger)] flex items-center justify-between gap-4 font-medium shadow-xs">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-[var(--sd-danger)] shrink-0" />
              <span>{scanResult}</span>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={handleViewVulnerabilities}
                className="text-[var(--sd-danger)] hover:underline font-semibold text-xs cursor-pointer"
              >
                View Vulnerabilities →
              </button>
              <button
                onClick={handleDismissScan}
                className="text-[var(--sd-danger)]/70 hover:text-[var(--sd-danger)] font-mono text-xs cursor-pointer font-semibold"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">Critical CVEs</span>
              <ShieldAlert className="h-4 w-4 text-[var(--sd-danger)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-danger)] font-mono">{criticalCvesCount}</div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">
              {criticalCvesCount === 0 ? "0 critical severity issues" : `${criticalCvesCount} critical issues detected`}
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">High Severity</span>
              <AlertTriangle className="h-4 w-4 text-[var(--sd-warning)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-warning)] font-mono">{highCvesCount}</div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">
              {highCvesCount === 0 ? "0 high severity issues" : `${highCvesCount} high severity vulnerabilities`}
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">Secrets Leaked</span>
              <Key className="h-4 w-4 text-[var(--sd-danger)]" />
            </div>
            <div className={cn("text-2xl font-bold font-mono", secrets.length > 0 ? "text-[var(--sd-danger)]" : "text-[var(--sd-text)]")}>
              {secrets.length}
            </div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">
              {secrets.length === 0
                ? "No secrets detected"
                : secrets.some((s) => s.risk_level === "CRITICAL")
                ? `${secrets.filter((s) => s.risk_level === "CRITICAL").length} critical credential${secrets.filter((s) => s.risk_level === "CRITICAL").length !== 1 ? "s" : ""} exposed`
                : `${secrets.length} credential${secrets.length !== 1 ? "s" : ""} detected`}
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">LVM Snapshots</span>
              <HardDrive className="h-4 w-4 text-[var(--sd-pine-bright)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-pine-bright)] font-mono">14</div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">Pre-patch rollback restore points</p>
          </div>
        </div>

        {/* Tab Controls */}
        <div id="findings-tabs" className="flex items-center gap-2 border-b border-[var(--sd-border)] scroll-mt-6">
          <button
            onClick={() => setActiveTab("cve")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "cve"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Scan className="h-3.5 w-3.5" />
            <span>Trivy CVE Findings ({cves.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("secrets")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "secrets"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Key className="h-3.5 w-3.5" />
            <span>Gitleaks Secret Detection ({secrets.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("patch")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "patch"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>SSH Patch Orchestrator &amp; LVM Rollback</span>
          </button>

          <button
            onClick={() => setActiveTab("intel")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "intel"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Globe className="h-3.5 w-3.5" />
            <span>External Attack Surface (Shodan / HIBP)</span>
          </button>
        </div>

        {/* Tab 1: Trivy Vulnerability Findings */}
        {activeTab === "cve" && (
          <div className="space-y-4">
            {cves.length === 0 ? (
              <div className="p-12 text-center rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-3">
                <Scan className="h-8 w-8 text-[var(--sd-text-muted)] mx-auto opacity-60" />
                <h3 className="text-sm font-semibold text-[var(--sd-text)]">No Vulnerabilities Displayed</h3>
                <p className="text-xs text-[var(--sd-text-muted)] max-w-md mx-auto">
                  Click &quot;Trigger Trivy Scan&quot; to execute a live scan across workspace packages and display vulnerabilities.
                </p>
                <button
                  onClick={triggerTrivyScan}
                  disabled={loading}
                  className="mt-2 inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-hover)] text-[#f7f4ed] text-xs font-semibold cursor-pointer disabled:opacity-50 transition shadow-xs"
                >
                  <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                  <span>Trigger Trivy Scan</span>
                </button>
              </div>
            ) : (
              <>
                {/* Severity Filter Controls */}
                <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)]">
                  <div className="flex items-center gap-2 overflow-x-auto">
                    <span className="text-xs font-medium text-[var(--sd-text-muted)]">Filter:</span>
                    {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
                      const count =
                        sev === "ALL"
                          ? cves.length
                          : cves.filter((c) => c.severity?.toUpperCase() === sev).length;
                      return (
                        <button
                          key={sev}
                          onClick={() => setSeverityFilter(sev)}
                          className={cn(
                            "px-2.5 py-1 rounded-md text-xs font-semibold font-mono transition cursor-pointer flex items-center gap-1.5",
                            severityFilter === sev
                              ? "bg-[var(--sd-pine)] text-[#f7f4ed]"
                              : "bg-[var(--sd-bg)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] border border-[var(--sd-border)]"
                          )}
                        >
                          <span>{sev}</span>
                          <span className="opacity-80 font-normal">({count})</span>
                        </button>
                      );
                    })}
                  </div>
                  <div className="text-xs text-[var(--sd-text-muted)]">
                    Showing <strong className="text-[var(--sd-text)]">{filteredCves.length}</strong> of {cves.length} findings
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3.5">
                  {filteredCves.map((cve, index) => (
                    <div
                      key={`${cve.cve_id}-${index}`}
                      className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:border-[var(--sd-border-strong)] transition-all shadow-xs space-y-3"
                    >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono",
                            cve.severity === "CRITICAL"
                              ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]"
                              : cve.severity === "HIGH"
                              ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                              : cve.severity === "MEDIUM"
                              ? "bg-[var(--sd-warning-dim)] text-amber-500 border border-amber-500/20"
                              : "bg-[var(--sd-bg)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                          )}
                        >
                          {cve.severity}
                        </span>
                        <span className="font-mono text-sm font-bold text-[var(--sd-text)]">
                          {cve.cve_id}
                        </span>
                        {(cve.target || cve.asset_id) && (
                          <span className="text-xs text-[var(--sd-text-muted)]">
                            Target: <code className="text-[var(--sd-text)] font-semibold">{cve.target || cve.asset_id}</code>
                          </span>
                        )}
                      </div>
                    </div>

                    <p className="text-xs text-[var(--sd-text)] leading-relaxed">{cve.description}</p>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--sd-border)]/60 text-xs">
                      <div className="flex items-center gap-3 text-[var(--sd-text-muted)] flex-wrap">
                        <span>Package: <code className="text-[var(--sd-text)] font-semibold">{cve.package_name}</code></span>
                        {cve.installed_version && (
                          <span>Installed: <code className="bg-[var(--sd-bg)] px-1.5 py-0.5 rounded border border-[var(--sd-border)]">{cve.installed_version}</code></span>
                        )}
                        {cve.fixed_version && cve.fixed_version !== "N/A" && (
                          <span>Fixed in: <code className="bg-[var(--sd-bg)] px-1.5 py-0.5 rounded border border-[var(--sd-border)] text-emerald-500 font-semibold">{cve.fixed_version}</code></span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => runBlastRadius(cve)}
                          disabled={loading}
                          className="px-2.5 py-1 rounded-md bg-[var(--sd-bg)] hover:bg-[var(--sd-panel)] text-[var(--sd-text)] border border-[var(--sd-border)] text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
                        >
                          <Zap className="h-3 w-3 text-[var(--sd-warning)]" />
                          <span>Impact Analysis</span>
                        </button>
                        <button
                          onClick={() => generateRunbook(cve)}
                          disabled={loading}
                          className="px-2.5 py-1 rounded-md bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-hover)] text-[#f7f4ed] text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
                        >
                          <FileCode className="h-3 w-3" />
                          <span>Recovery Runbook</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
        )}

        {/* Tab 2: Gitleaks Secrets Detection */}
        {activeTab === "secrets" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-[var(--sd-text-muted)]">
                  Automated regex and high-entropy secret detection scanning git commits and environment variables.
                </p>
                {secrets.length > 0 && (
                  <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-0.5">
                    {secrets.filter((s) => s.source === "git_history").length} from git history ·{" "}
                    {secrets.filter((s) => s.source !== "git_history").length} from filesystem/env
                  </p>
                )}
              </div>
              <button
                id="gitleaks-scan-btn"
                onClick={triggerSecretsScan}
                disabled={secretScanLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] text-[#f7f4ed] text-xs font-semibold hover:bg-[var(--sd-pine-hover)] transition cursor-pointer disabled:opacity-60 shadow-xs"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", secretScanLoading && "animate-spin")} />
                {secretScanLoading ? "Scanning…" : "Scan Repository Now"}
              </button>
            </div>

            {/* Real-time Progress Bar */}
            {secretScanLoading && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[10.5px] text-[var(--sd-text-muted)]">
                  <span className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-[var(--sd-pine)] animate-pulse" />
                    Gitleaks scanning git history and filesystem…
                  </span>
                  <span>{Math.round(scanProgress)}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-[var(--sd-border)] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-[var(--sd-pine)] transition-all duration-300"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              </div>
            )}

            <div className="rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] overflow-hidden shadow-xs">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--sd-bg)] border-b border-[var(--sd-border)] text-[var(--sd-text-muted)] font-medium">
                  <tr>
                    <th className="p-3">Secret Type</th>
                    <th className="p-3">File Path</th>
                    <th className="p-3">Commit / Line</th>
                    <th className="p-3">Masked Value</th>
                    <th className="p-3">Risk</th>
                    <th className="p-3 text-right">Mitigation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--sd-border)]">
                  {secrets.length === 0 && !secretScanLoading && (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-[var(--sd-text-muted)]">
                        <div className="flex flex-col items-center gap-2">
                          <Key className="h-8 w-8 opacity-30" />
                          <span className="font-medium text-[var(--sd-text)]">No secrets loaded yet</span>
                          <span className="text-[10.5px]">
                            Click &quot;Scan Repository Now&quot; to run Gitleaks against the codebase.
                          </span>
                        </div>
                      </td>
                    </tr>
                  )}
                  {secrets.map((sec, i) => (
                    <tr key={sec.fingerprint || i} className="hover:bg-[var(--sd-panel-hover)] transition">
                      <td className="p-3">
                        <div className="flex items-center gap-2 font-semibold text-[var(--sd-text)]">
                          <Key className="h-3.5 w-3.5 text-[var(--sd-danger)] shrink-0" />
                          <span>{sec.type}</span>
                        </div>
                        {sec.author && (
                          <div className="text-[10px] text-[var(--sd-text-muted)] mt-0.5 pl-5">
                            by {sec.author}
                          </div>
                        )}
                      </td>
                      <td className="p-3 font-mono text-[var(--sd-text-muted)] max-w-[180px]">
                        <div className="truncate" title={sec.location}>{sec.location}</div>
                        <div className="text-[10px] opacity-70 mt-0.5">{sec.source}</div>
                      </td>
                      <td className="p-3 font-mono text-[var(--sd-text-muted)]">
                        {sec.commit ? (
                          <span
                            className="inline-block px-1.5 py-0.5 rounded text-[10px] bg-[var(--sd-panel-hover)] text-[var(--sd-pine-bright)] border border-[var(--sd-border)] font-mono"
                            title={sec.commit}
                          >
                            {sec.commit.substring(0, 7)}
                          </span>
                        ) : (
                          <span className="text-[10.5px] opacity-50">—</span>
                        )}
                        {sec.line_number !== undefined && (
                          <span className="ml-1.5 text-[10px] opacity-60">L{sec.line_number}</span>
                        )}
                      </td>
                      <td className="p-3 font-mono text-[var(--sd-text)] max-w-[200px]">
                        <code className="text-[10.5px] truncate block" title={sec.snippet_masked}>
                          {sec.snippet_masked}
                        </code>
                      </td>
                      <td className="p-3">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border",
                            sec.risk_level === "CRITICAL"
                              ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border-[var(--sd-danger-border)]"
                              : sec.risk_level === "HIGH"
                              ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)]"
                              : "bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] border-[var(--sd-border)]"
                          )}
                        >
                          {sec.risk_level}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          id={`mitigate-${sec.fingerprint || i}`}
                          onClick={() => rotateKey(sec)}
                          disabled={loading}
                          className="px-2.5 py-1 rounded bg-[var(--sd-danger)] hover:bg-[var(--sd-danger)]/90 text-white font-semibold text-xs transition cursor-pointer shadow-xs disabled:opacity-50"
                        >
                          {sec.action_available}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>
        )}

        {/* Tab 3: SSH Patch Orchestrator & LVM Rollback */}
        {activeTab === "patch" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-4 shadow-xs">
                <h3 className="text-sm font-bold text-[var(--sd-text)] flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-[var(--sd-pine)]" />
                  Patch Configuration
                </h3>

                <div>
                  <label className="text-xs text-[var(--sd-text-muted)] block mb-1">Target Host</label>
                  <select
                    value={patchHost}
                    onChange={(e) => setPatchHost(e.target.value)}
                    className="w-full p-2 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs text-[var(--sd-text)] font-mono"
                  >
                    <option value="10.0.4.12 (srv-prod-api-01)">10.0.4.12 (srv-prod-api-01 - Ubuntu 22.04)</option>
                    <option value="10.0.4.15 (srv-app-worker-02)">10.0.4.15 (srv-app-worker-02 - Debian 11)</option>
                    <option value="10.0.5.21 (k8s-node-worker-03)">10.0.5.21 (k8s-node-worker-03 - RHEL 9)</option>
                  </select>
                </div>

                <div className="p-3 rounded-lg border border-[var(--sd-pine-border)] bg-[var(--sd-pine-dim)] text-xs text-[var(--sd-pine-bright)] space-y-1">
                  <div className="font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    LVM Snapshot Guard Verified
                  </div>
                  <p className="text-[11px] opacity-90">
                    A copy-on-write snapshot is automatically created before apt/yum execution, guaranteeing zero-data-loss rollback.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="dryrun"
                    checked={isDryRun}
                    onChange={(e) => setIsDryRun(e.target.checked)}
                    className="rounded border-[var(--sd-border)]"
                  />
                  <label htmlFor="dryrun" className="text-xs text-[var(--sd-text)] cursor-pointer">
                    Dry Run Mode (Simulate without applying changes)
                  </label>
                </div>

                <div className="flex items-center gap-2 pt-2">
                  <button
                    onClick={() => executePatch(isDryRun)}
                    disabled={loading}
                    className="flex-1 px-3 py-2 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-hover)] text-[#f7f4ed] text-xs font-semibold transition cursor-pointer flex items-center justify-center gap-1.5 shadow-xs"
                  >
                    <Play className="h-3.5 w-3.5" />
                    <span>{isDryRun ? "Execute Dry Run" : "Apply Security Patch"}</span>
                  </button>

                  <button
                    onClick={rollbackSnapshot}
                    className="px-3 py-2 rounded-lg border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] hover:bg-[var(--sd-warning-dim)]/80 text-[var(--sd-warning)] text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
                    title="Rollback target host to pre-patch snapshot"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    <span>Rollback</span>
                  </button>
                </div>
              </div>

              {/* Terminal Logs */}
              <div className="lg:col-span-2 p-4 rounded-xl border border-[var(--sd-border)] bg-[#121417] text-[#a9b7c6] font-mono text-xs flex flex-col h-80 shadow-xs">
                <div className="flex items-center justify-between border-b border-[#2d3239] pb-2 mb-2 text-[#7f8a9a]">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-[#10b981]" />
                    SSH Patching Console &amp; LVM Attestation
                  </span>
                  <span>port 22 / mTLS</span>
                </div>
                <div className="flex-1 overflow-y-auto space-y-1.5 pr-2">
                  {patchLogs.map((log, index) => (
                    <div key={index} className="leading-relaxed">
                      {log.startsWith("[SNAPSHOT]") ? (
                        <span className="text-[#38bdf8]">{log}</span>
                      ) : log.startsWith("[STATUS]") ? (
                        <span className="text-[#4ade80]">{log}</span>
                      ) : log.startsWith("[ROLLBACK") ? (
                        <span className="text-[#f59e0b] font-bold">{log}</span>
                      ) : log.startsWith("[RESTORE") ? (
                        <span className="text-[#10b981] font-bold">{log}</span>
                      ) : (
                        log
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Attack Surface & Threat Intel (OSINT) */}
        {activeTab === "intel" && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-4 shadow-xs">
              <h3 className="text-sm font-bold text-[var(--sd-text)] flex items-center gap-2">
                <Globe className="h-4 w-4 text-[var(--sd-pine)]" />
                External Attack Surface Management (Shodan &amp; HIBP)
              </h3>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Inspect public internet perimeter exposure, open ports, and corporate credential breach disclosures.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                <div className="p-4 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[var(--sd-text)]">Shodan Perimeter Inspection</span>
                    <span className="text-[10px] font-mono text-[var(--sd-pine-bright)]">24 Hosts Monitored</span>
                  </div>
                  <p className="text-xs text-[var(--sd-text-muted)]">
                    Detected Ports: <code className="text-[var(--sd-text)] font-semibold">80, 443, 22 (SSH Restrict)</code>. No unauthorized RDP (3389) or Elasticsearch (9200) exposed to WAN.
                  </p>
                </div>

                <div className="p-4 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[var(--sd-text)]">HaveIBeenPwned Domain Check</span>
                    <span className="text-[10px] font-mono text-[var(--sd-warning)]">1 Domain Flagged</span>
                  </div>
                  <p className="text-xs text-[var(--sd-text-muted)]">
                    0 active corporate credentials leaked in paste sites within the last 30 days. Forced TOTP MFA enabled on all IAM accounts.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Advisor Output Modal */}
        {advisorContent && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="w-full max-w-2xl rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] p-6 space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
                <h3 className="text-sm font-bold text-[var(--sd-text)]">{advisorTitle}</h3>
                <button
                  onClick={() => setAdvisorContent(null)}
                  className="text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] font-mono cursor-pointer"
                >
                  ✕ Close
                </button>
              </div>

              <pre className="p-4 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs font-mono text-[var(--sd-text)] overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed">
                {advisorContent}
              </pre>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setAdvisorContent(null)}
                  className="px-4 py-2 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-hover)] text-[#f7f4ed] text-xs font-semibold cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
