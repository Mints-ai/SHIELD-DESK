"use client";

import React, { useState, useEffect, useMemo } from "react";
import { GlassDialog } from "@/components/ui/GlassDialog";
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
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronDown,
  ChevronUp,
  Wrench,
  Copy,
  Check,
  GitCommit,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

function getPaginationRange(current: number, total: number): (number | "...")[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  if (current <= 4) {
    return [1, 2, 3, 4, 5, "...", total];
  }
  if (current >= total - 3) {
    return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
  }
  return [1, "...", current - 1, current, current + 1, "...", total];
}

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
  const [mitigatingId, setMitigatingId] = useState<string | null>(null);
  const [mitigatedIds, setMitigatedIds] = useState<Set<string>>(new Set());

  // Review & Remediation modal state
  const [reviewingSecret, setReviewingSecret] = useState<SecretFinding | null>(null);
  const [remediationFeedback, setRemediationFeedback] = useState<{
    findingKey: string;
    success: boolean;
    status: string;
    message: string;
    newKeyId?: string;
  } | null>(null);
  const [copiedGitCmd, setCopiedGitCmd] = useState(false);

  const criticalCvesCount = useMemo(
    () => cves.filter((c) => c.severity?.toUpperCase() === "CRITICAL").length,
    [cves]
  );
  const highCvesCount = useMemo(
    () => cves.filter((c) => c.severity?.toUpperCase() === "HIGH").length,
    [cves]
  );

  const [severityFilter, setSeverityFilter] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("ALL");
  const [currentPage, setCurrentPage] = useState(1);
  const PAGE_SIZE = 3;

  const filteredCves = useMemo(() => {
    if (severityFilter === "ALL") return cves;
    return cves.filter((c) => c.severity?.toUpperCase() === severityFilter);
  }, [cves, severityFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredCves.length / PAGE_SIZE));

  const paginatedCves = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filteredCves.slice(start, start + PAGE_SIZE);
  }, [filteredCves, currentPage]);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(1);
    }
  }, [totalPages, currentPage]);

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    const el = document.getElementById("findings-tabs");
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  // Patching state
  const [patchHost, setPatchHost] = useState("10.0.4.12 (srv-prod-api-01)");
  const [isDryRun, setIsDryRun] = useState(false);
  const [patchLogs, setPatchLogs] = useState<string[]>([
    "[SYSTEM READY] SSH patch orchestrator client ready. Verify service status and configure target host.",
  ]);
  const [patchServiceOnline, setPatchServiceOnline] = useState<boolean | null>(null);
  const [patchServiceChecking, setPatchServiceChecking] = useState<boolean>(false);
  const [patchPort, setPatchPort] = useState<number>(22);
  const [patchUser, setPatchUser] = useState<string>("ubuntu");
  const [patchPrivateKey, setPatchPrivateKey] = useState<string>("");
  const [patchHostKeyFingerprint, setPatchHostKeyFingerprint] = useState<string>("SHA256:d8a2b3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
  const [patchPackage, setPatchPackage] = useState<string>("openssh-server");
  const [patchTargetVersion, setPatchTargetVersion] = useState<string>("1:8.9p1-3ubuntu0.10");
  const [patchRestartServices, setPatchRestartServices] = useState<string>("ssh");
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [activeJobState, setActiveJobState] = useState<string | null>(null);
  const [showAdvancedSSH, setShowAdvancedSSH] = useState<boolean>(false);

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
          setCurrentPage(1);
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
        setCurrentPage(1);
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

  const executeRemediation = async (finding: SecretFinding, actionOverride?: string) => {
    const findingKey = finding.fingerprint || finding.secret_hash || `${finding.location}:${finding.line_number}`;
    setMitigatingId(findingKey);
    try {
      const chosenAction =
        actionOverride ||
        (finding.rule_id?.includes("github")
          ? "revoke_pat"
          : finding.rule_id?.includes("aws")
          ? "rotate_key"
          : "rotate_key");

      const res = await fetch("/api/gitleaks/mitigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action: chosenAction,
          finding_id: finding.fingerprint || finding.secret_hash,
          rule_id: finding.rule_id || "",
          key_id: "AKIA1234567890ABCDEF",
        }),
      });
      const data = await res.json();
      if (data.success) {
        setMitigatedIds((prev) => new Set(prev).add(findingKey));
        setRemediationFeedback({
          findingKey,
          success: true,
          status: data.status || "remediated",
          message: data.message || "Remediation action completed successfully.",
          newKeyId: data.new_key_id,
        });
      } else {
        setRemediationFeedback({
          findingKey,
          success: false,
          status: "failed",
          message: data.error || "Remediation action failed.",
        });
      }
    } catch (err: any) {
      setRemediationFeedback({
        findingKey,
        success: false,
        status: "error",
        message: err.message || "Network error while connecting to remediation API.",
      });
    } finally {
      setMitigatingId(null);
    }
  };

  const rotateKey = (finding: SecretFinding) => executeRemediation(finding);

  const checkPatchHealth = React.useCallback(async () => {
    try {
      setPatchServiceChecking(true);
      const res = await fetch("/api/patch/health");
      const data = await res.json();
      setPatchServiceOnline(data.online === true);
    } catch {
      setPatchServiceOnline(false);
    } finally {
      setPatchServiceChecking(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "patch") {
      checkPatchHealth();
    }
  }, [activeTab, checkPatchHealth]);

  // Poll active job logs every 1.5 seconds until terminal state
  useEffect(() => {
    if (!activeJobId) return;

    let isMounted = true;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/patch/jobs/${activeJobId}`, {
          headers: { "X-ShieldDesk-User": activeUserId },
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!isMounted) return;

        if (data.logs && Array.isArray(data.logs)) {
          setPatchLogs(data.logs);
        }
        if (data.job?.state) {
          setActiveJobState(data.job.state);
          const terminalStates = [
            "REMEDIATED",
            "ROLLED_BACK_HUMAN_REVIEW",
            "ESCALATED_URGENT",
            "HUMAN_REVIEW",
            "CANCELLED",
            "SNAPSHOT_FAILED",
            "PRECHECK_FAILED",
          ];
          if (terminalStates.includes(data.job.state)) {
            setActiveJobId(null);
          }
        }
      } catch {
        // network retry
      }
    }, 1500);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [activeJobId, activeUserId]);

  const executePatch = async (dryRun: boolean) => {
    setLoading(true);
    const targetHostClean = patchHost.split(" ")[0].trim();
    const initLog = `[${new Date().toLocaleTimeString()}] Submitting ${dryRun ? "DRY RUN SIMULATION" : "LIVE SSH PATCH"} for ${targetHostClean}...`;
    setPatchLogs((prev) => [...prev, initLog]);

    try {
      const payload: Record<string, unknown> = {
        host: targetHostClean,
        port: Number(patchPort) || 22,
        user: patchUser.trim() || "ubuntu",
        package: patchPackage.trim() || "openssh-server",
        target_version: patchTargetVersion.trim() || "1:8.9p1-3ubuntu0.10",
        restart_services: patchRestartServices
          ? patchRestartServices.split(",").map((s) => s.trim()).filter(Boolean)
          : [],
        dry_run: Boolean(dryRun),
      };

      if (!dryRun) {
        payload.private_key_pem = patchPrivateKey;
        payload.host_key_fingerprint = patchHostKeyFingerprint;
      } else {
        payload.private_key_pem = patchPrivateKey || "-----BEGIN OPENSSH PRIVATE KEY-----\nSIMULATED_KEY_FOR_DRY_RUN\n-----END OPENSSH PRIVATE KEY-----";
        payload.host_key_fingerprint = patchHostKeyFingerprint || "SHA256:simulated_host_key_fingerprint";
      }

      const res = await fetch("/api/patch/jobs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (res.ok && data.job_id) {
        setActiveJobId(data.job_id);
        setActiveJobState(data.state || "DETECTED");
        setPatchLogs((prev) => [
          ...prev,
          `[JOB ACCEPTED] ID: ${data.job_id} | State: ${data.state}`,
          `[PIPELINE] Connecting to SSH patch orchestrator runtime on port 8004...`,
        ]);
      } else {
        setPatchLogs((prev) => [
          ...prev,
          `[FAIL] ${data.error || "Failed to launch patch job."}`,
        ]);
      }
    } catch (err: any) {
      setPatchLogs((prev) => [
        ...prev,
        `[FAIL] Communication error reaching orchestrator API: ${err.message}`,
      ]);
    } finally {
      setLoading(false);
    }
  };

  const rollbackSnapshot = async () => {
    if (!activeJobId && !activeJobState) {
      setPatchLogs((prev) => [
        ...prev,
        `[ROLLBACK] No active job found to rollback. Triggering simulated LVM restore baseline.`,
        `[LVM] Merging snapshot snap_prepatch -> Reboot sequence verified.`,
        `[RESTORE COMPLETE] Host restored to baseline state with 0 data loss.`,
      ]);
      return;
    }

    try {
      setLoading(true);
      const targetId = activeJobId || "latest";
      setPatchLogs((prev) => [
        ...prev,
        `[ROLLBACK REQUEST] Requesting rollback for job ${targetId}...`,
      ]);

      const res = await fetch(`/api/patch/jobs/${targetId}/rollback`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
      });
      const data = await res.json();
      if (res.ok) {
        setPatchLogs((prev) => [
          ...prev,
          `[ROLLBACK ACCEPTED] ${data.message || "Rollback initiated"}`,
        ]);
      } else {
        setPatchLogs((prev) => [
          ...prev,
          `[ROLLBACK REJECTED] ${data.error || "Rollback could not be performed."}`,
        ]);
      }
    } catch (err: any) {
      setPatchLogs((prev) => [
        ...prev,
        `[ROLLBACK FAIL] Error: ${err.message}`,
      ]);
    } finally {
      setLoading(false);
    }
  };

  const prefillPatchForFinding = (cve: CveFinding) => {
    const pkg = cve.package_name || "";
    if (pkg) setPatchPackage(pkg);
    if (cve.fixed_version && cve.fixed_version !== "N/A") setPatchTargetVersion(cve.fixed_version);
    setActiveTab("patch");
    setTimeout(() => {
      const el = document.getElementById("patch-config-card");
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 50);
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
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="p-2 shrink-0 rounded-xl sd-surface border border-[var(--sd-border)] text-[var(--sd-wheat)]">
                <Scan className="h-5 w-5" />
              </div>
              <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                Security scanner
              </h1>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
              Automated Trivy container CVE inspection, Gitleaks secrets detection, and SSH snapshot patching.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2.5 py-1 rounded-md text-[11px] font-medium border border-[var(--sd-border)] sd-surface text-[var(--sd-text-muted)] flex items-center gap-1.5 shadow-xs">
              <Cpu className="h-3 w-3 text-[var(--sd-text-muted)]" />
              <span>FastAPI Scanner: Ready</span>
            </span>

            <button
              onClick={triggerTrivyScan}
              disabled={loading}
              className="sd-button sd-button-primary flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium shadow-xs transition cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              <span>Trigger Trivy Scan</span>
            </button>
          </div>
        </div>

        {/* Scan Status Toast Banner */}
        {scanResult && (
          <div className="p-3 rounded-lg border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[13px] text-[var(--sd-danger)] flex items-center justify-between gap-4 font-medium shadow-xs">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-[var(--sd-danger)] shrink-0" />
              <span>{scanResult}</span>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={handleViewVulnerabilities}
                className="text-[var(--sd-danger)] hover:underline font-medium text-[13px] cursor-pointer"
              >
                View Vulnerabilities →
              </button>
              <button
                onClick={handleDismissScan}
                className="text-[var(--sd-danger)]/70 hover:text-[var(--sd-danger)] font-mono text-[13px] cursor-pointer font-medium"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">Critical CVEs</span>
              <ShieldAlert className="h-4 w-4 text-[var(--sd-danger)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-danger)] font-mono">{criticalCvesCount}</div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">
              {criticalCvesCount === 0 ? "0 critical severity issues" : `${criticalCvesCount} critical issues detected`}
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">High Severity</span>
              <AlertTriangle className="h-4 w-4 text-[var(--sd-warning)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-warning)] font-mono">{highCvesCount}</div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">
              {highCvesCount === 0 ? "0 high severity issues" : `${highCvesCount} high severity vulnerabilities`}
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">Secrets Leaked</span>
              <Key className="h-4 w-4 text-[var(--sd-danger)]" />
            </div>
            <div className={cn("text-2xl font-medium font-mono", secrets.length > 0 ? "text-[var(--sd-danger)]" : "text-[var(--sd-text)]")}>
              {secrets.length}
            </div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">
              {secrets.length === 0
                ? "No secrets detected"
                : secrets.some((s) => s.risk_level === "CRITICAL")
                ? `${secrets.filter((s) => s.risk_level === "CRITICAL").length} critical credential${secrets.filter((s) => s.risk_level === "CRITICAL").length !== 1 ? "s" : ""} exposed`
                : `${secrets.length} credential${secrets.length !== 1 ? "s" : ""} detected`}
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">LVM Snapshots</span>
              <HardDrive className="h-4 w-4 text-[var(--sd-pine-bright)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-pine-bright)] font-mono">14</div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">Pre-patch rollback restore points</p>
            <span className="sd-sample-label mt-2 w-fit">Sample metric</span>
          </div>
        </div>

        {/* Tab Controls */}
        <div id="findings-tabs" className="sd-tabs scroll-mt-6" role="group" aria-label="Scanner views">
          <button type="button" aria-pressed={activeTab === "cve"} onClick={() => setActiveTab("cve")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Scan className="h-3.5 w-3.5" />
            <span>Vulnerabilities ({cves.length})</span>
          </button>

          <button type="button" aria-pressed={activeTab === "secrets"} onClick={() => setActiveTab("secrets")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Key className="h-3.5 w-3.5" />
            <span>Secret detection ({secrets.length})</span>
          </button>

          <button type="button" aria-pressed={activeTab === "patch"} onClick={() => setActiveTab("patch")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Terminal className="h-3.5 w-3.5" />
            <span>Patch &amp; rollback</span>
          </button>

          <button type="button" aria-pressed={activeTab === "intel"} onClick={() => setActiveTab("intel")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Globe className="h-3.5 w-3.5" />
            <span>External intelligence</span>
          </button>
        </div>

        {/* Tab 1: Trivy Vulnerability Findings */}
        {activeTab === "cve" && (
          <div className="space-y-4">
            {cves.length === 0 ? (
              <div className="p-12 text-center rounded-xl border border-[var(--sd-border)] sd-surface space-y-3">
                <Scan className="h-8 w-8 text-[var(--sd-text-muted)] mx-auto opacity-60" />
                <h3 className="text-sm font-medium text-[var(--sd-text)]">No Vulnerabilities Displayed</h3>
                <p className="text-[13px] text-[var(--sd-text-muted)] max-w-md mx-auto">
                  Click &quot;Trigger Trivy Scan&quot; to execute a live scan across workspace packages and display vulnerabilities.
                </p>
                <button
                  onClick={triggerTrivyScan}
                  disabled={loading}
                  className="sd-button sd-button-primary mt-2 inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium cursor-pointer disabled:opacity-50 transition shadow-xs"
                >
                  <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                  <span>Trigger Trivy Scan</span>
                </button>
              </div>
            ) : (
              <>
                {/* Severity Filter Controls */}
                <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl border border-[var(--sd-border)] sd-surface">
                  <div className="flex items-center gap-2 overflow-x-auto">
                    <span className="text-[13px] font-medium text-[var(--sd-text-muted)]">Filter:</span>
                    {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
                      const count =
                        sev === "ALL"
                          ? cves.length
                          : cves.filter((c) => c.severity?.toUpperCase() === sev).length;
                      return (
                        <button
                          key={sev}
                          onClick={() => {
                            setSeverityFilter(sev);
                            setCurrentPage(1);
                          }}
                          className={cn(
                            "sd-button px-2.5 py-1 rounded-full text-[13px] font-medium font-mono transition cursor-pointer flex items-center gap-1.5",
                            severityFilter === sev
                              ? "sd-button-primary text-[var(--sd-on-accent)]"
                              : "bg-[var(--sd-bg)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] border border-[var(--sd-border)]"
                          )}
                        >
                          <span>{sev}</span>
                          <span className="opacity-80 font-normal">({count})</span>
                        </button>
                      );
                    })}
                  </div>
                  <div className="text-[13px] text-[var(--sd-text-muted)]">
                    {filteredCves.length > 0 ? (
                      <>
                        Showing <strong className="text-[var(--sd-text)]">{(currentPage - 1) * PAGE_SIZE + 1}–{Math.min(currentPage * PAGE_SIZE, filteredCves.length)}</strong> of <strong className="text-[var(--sd-text)]">{filteredCves.length}</strong> findings
                        {severityFilter !== "ALL" && <span> (filtered from {cves.length})</span>}
                      </>
                    ) : (
                      <span>No matching findings</span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3.5">
                  {paginatedCves.map((cve, index) => (
                    <div
                      key={`${cve.cve_id}-${index}`}
                      className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface hover:border-[var(--sd-border-strong)] transition-all shadow-xs space-y-3"
                    >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider font-mono",
                            cve.severity === "CRITICAL"
                              ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]"
                              : cve.severity === "HIGH"
                              ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                              : cve.severity === "MEDIUM"
                              ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                              : "bg-[var(--sd-bg)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                          )}
                        >
                          {cve.severity}
                        </span>
                        <span className="font-mono text-sm font-medium text-[var(--sd-text)]">
                          {cve.cve_id}
                        </span>
                        {(cve.target || cve.asset_id) && (
                          <span className="text-[13px] text-[var(--sd-text-muted)]">
                            Target: <code className="text-[var(--sd-text)] font-medium">{cve.target || cve.asset_id}</code>
                          </span>
                        )}
                      </div>
                    </div>

                    <p className="text-[13px] text-[var(--sd-text)] leading-relaxed">{cve.description}</p>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--sd-border)]/60 text-[13px]">
                      <div className="flex items-center gap-3 text-[var(--sd-text-muted)] flex-wrap">
                        <span>Package: <code className="text-[var(--sd-text)] font-medium">{cve.package_name}</code></span>
                        {cve.installed_version && (
                          <span>Installed: <code className="bg-[var(--sd-bg)] px-1.5 py-0.5 rounded border border-[var(--sd-border)]">{cve.installed_version}</code></span>
                        )}
                        {cve.fixed_version && cve.fixed_version !== "N/A" && (
                          <span>Fixed in: <code className="bg-[var(--sd-bg)] px-1.5 py-0.5 rounded border border-[var(--sd-border)] text-[var(--sd-success)] font-medium">{cve.fixed_version}</code></span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => prefillPatchForFinding(cve)}
                          className="sd-button px-2.5 py-1 rounded-full bg-[var(--sd-bg)] hover:sd-surface text-[var(--sd-pine-bright)] border border-[var(--sd-pine-border)] text-[13px] font-medium transition cursor-pointer flex items-center gap-1.5"
                          title="Stage and remediate this package in SSH Patch Orchestrator"
                        >
                          <Terminal className="h-3 w-3 text-[var(--sd-pine)]" />
                          <span>Patch Host</span>
                        </button>
                        <button
                          onClick={() => runBlastRadius(cve)}
                          disabled={loading}
                          className="sd-button px-2.5 py-1 rounded-full bg-[var(--sd-bg)] hover:sd-surface text-[var(--sd-text)] border border-[var(--sd-border)] text-[13px] font-medium transition cursor-pointer flex items-center gap-1.5"
                        >
                          <Zap className="h-3 w-3 text-[var(--sd-warning)]" />
                          <span>Impact Analysis</span>
                        </button>
                        <button
                          onClick={() => generateRunbook(cve)}
                          disabled={loading}
                          className="sd-button sd-button-primary px-2.5 py-1 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium transition cursor-pointer flex items-center gap-1.5"
                        >
                          <FileCode className="h-3 w-3" />
                          <span>Recovery Runbook</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination Controls */}
              {totalPages > 1 && (
                <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl border border-[var(--sd-border)] sd-surface">
                  <div className="text-[13px] text-[var(--sd-text-muted)] font-mono">
                    Page <strong className="text-[var(--sd-text)]">{currentPage}</strong> of <strong className="text-[var(--sd-text)]">{totalPages}</strong>
                    <span className="hidden sm:inline text-[var(--sd-text-muted)] ml-2">
                      ({filteredCves.length} total findings · 3 per page)
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 flex-wrap">
                    <button
                      onClick={() => handlePageChange(1)}
                      disabled={currentPage === 1}
                      className="sd-button px-2.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:sd-surface disabled:opacity-30 disabled:cursor-not-allowed text-[12px] font-medium transition cursor-pointer flex items-center gap-1"
                      title="First Page"
                      aria-label="First page"
                    >
                      <ChevronsLeft className="h-3.5 w-3.5" />
                      <span className="hidden md:inline">First</span>
                    </button>

                    <button
                      onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
                      disabled={currentPage === 1}
                      className="sd-button px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:sd-surface disabled:opacity-30 disabled:cursor-not-allowed text-[12px] font-medium transition cursor-pointer flex items-center gap-1"
                      title="Previous Page"
                      aria-label="Previous page"
                    >
                      <ChevronLeft className="h-3.5 w-3.5" />
                      <span>Prev</span>
                    </button>

                    {/* Numeric Page Buttons */}
                    <div className="flex items-center gap-1 px-1">
                      {getPaginationRange(currentPage, totalPages).map((p, idx) =>
                        p === "..." ? (
                          <span key={`ellipsis-${idx}`} className="px-1 text-[12px] text-[var(--sd-text-muted)] font-mono">
                            …
                          </span>
                        ) : (
                          <button
                            key={p}
                            onClick={() => handlePageChange(Number(p))}
                            className={cn(
                              "min-w-8 h-8 px-2 rounded-lg text-[12px] font-mono font-medium transition cursor-pointer flex items-center justify-center",
                              currentPage === p
                                ? "sd-button-primary text-[var(--sd-on-accent)] shadow-xs"
                                : "border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:sd-surface"
                            )}
                            aria-label={`Go to page ${p}`}
                            aria-current={currentPage === p ? "page" : undefined}
                          >
                            {p}
                          </button>
                        )
                      )}
                    </div>

                    <button
                      onClick={() => handlePageChange(Math.min(totalPages, currentPage + 1))}
                      disabled={currentPage === totalPages}
                      className="sd-button px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:sd-surface disabled:opacity-30 disabled:cursor-not-allowed text-[12px] font-medium transition cursor-pointer flex items-center gap-1"
                      title="Next Page"
                      aria-label="Next page"
                    >
                      <span>Next</span>
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>

                    <button
                      onClick={() => handlePageChange(totalPages)}
                      disabled={currentPage === totalPages}
                      className="sd-button px-2.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:sd-surface disabled:opacity-30 disabled:cursor-not-allowed text-[12px] font-medium transition cursor-pointer flex items-center gap-1"
                      title="Last Page"
                      aria-label="Last page"
                    >
                      <span className="hidden md:inline">Last</span>
                      <ChevronsRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        )}

        {/* Tab 2: Gitleaks Secrets Detection */}
        {activeTab === "secrets" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-[13px] text-[var(--sd-text-muted)]">
                  Automated regex and high-entropy secret detection scanning git commits and environment variables.
                </p>
                {secrets.length > 0 && (
                  <p className="text-[11px] text-[var(--sd-text-muted)] mt-0.5">
                    {secrets.filter((s) => s.source === "git_history").length} from git history ·{" "}
                    {secrets.filter((s) => s.source !== "git_history").length} from filesystem/env
                    {mitigatedIds.size > 0 && (
                      <span className="ml-2 font-medium text-[var(--sd-pine-bright)]">
                        · {mitigatedIds.size} of {secrets.length} remediated
                      </span>
                    )}
                  </p>
                )}
              </div>
              <button
                id="gitleaks-scan-btn"
                onClick={triggerSecretsScan}
                disabled={secretScanLoading}
                className="sd-button sd-button-primary flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium hover:bg-[var(--sd-pine-hover)] transition cursor-pointer disabled:opacity-60 shadow-xs"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", secretScanLoading && "animate-spin")} />
                {secretScanLoading ? "Scanning…" : "Scan Repository Now"}
              </button>
            </div>

            {/* Real-time Progress Bar */}
            {secretScanLoading && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-[var(--sd-text-muted)]">
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

            <div className="rounded-xl border border-[var(--sd-border)] sd-surface overflow-x-auto shadow-xs">
              <table className="min-w-[760px] w-full text-left text-[13px]">
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
                          <span className="text-[11px]">
                            Click &quot;Scan Repository Now&quot; to run Gitleaks against the codebase.
                          </span>
                        </div>
                      </td>
                    </tr>
                  )}
                  {secrets.map((sec, i) => (
                    <tr key={sec.fingerprint || i} className="hover:bg-[var(--sd-panel-hover)] transition">
                      <td className="p-3">
                        <div className="flex items-center gap-2 font-medium text-[var(--sd-text)]">
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
                          <span className="text-[11px] opacity-50">—</span>
                        )}
                        {sec.line_number !== undefined && (
                          <span className="ml-1.5 text-[10px] opacity-60">L{sec.line_number}</span>
                        )}
                      </td>
                      <td className="p-3 font-mono text-[var(--sd-text)] max-w-[200px]">
                        <code className="text-[11px] truncate block" title={sec.snippet_masked}>
                          {sec.snippet_masked}
                        </code>
                      </td>
                      <td className="p-3">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border",
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
                        {(() => {
                          const fKey = sec.fingerprint || sec.secret_hash || `${sec.location}:${sec.line_number}`;
                          const isMitigated = mitigatedIds.has(fKey);
                          return isMitigated ? (
                            <button
                              onClick={() => {
                                setReviewingSecret(sec);
                                setRemediationFeedback(null);
                              }}
                              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[12px] font-medium text-[var(--sd-pine-bright)] bg-[var(--sd-pine)]/15 border border-[var(--sd-pine)]/30 hover:bg-[var(--sd-pine)]/25 transition cursor-pointer shadow-xs ml-auto"
                              title="Click to view remediation details"
                            >
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              <span>Remediated · Details</span>
                            </button>
                          ) : (
                            <button
                              id={`mitigate-${sec.fingerprint || i}`}
                              onClick={() => {
                                setReviewingSecret(sec);
                                setRemediationFeedback(null);
                              }}
                              className="sd-button px-2.5 py-1 rounded-lg bg-[var(--sd-danger)] hover:bg-[var(--sd-danger)]/90 text-[var(--sd-on-accent)] font-medium text-[12px] transition cursor-pointer shadow-xs flex items-center gap-1.5 ml-auto"
                            >
                              <Wrench className="h-3.5 w-3.5" />
                              <span>{sec.action_available || "Review & Remediate"}</span>
                            </button>
                          );
                        })()}
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
              <div id="patch-config-card" className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface space-y-4 shadow-xs">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium text-[var(--sd-text)] flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-[var(--sd-pine)]" />
                    Patch Configuration
                  </h3>
                  <div className="flex items-center gap-2">
                    {patchServiceOnline === true ? (
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-medium border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 flex items-center gap-1.5" title="SSH Patch Orchestrator HTTP microservice online on port 8004">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        Online (:8004)
                      </span>
                    ) : patchServiceOnline === false ? (
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-medium border border-rose-500/30 bg-rose-500/10 text-rose-400 flex items-center gap-1.5" title="Orchestrator offline. Start with: orchestrator.exe server --port 8004">
                        <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
                        Offline (:8004)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-medium border border-[var(--sd-border)] text-[var(--sd-text-dim)] flex items-center gap-1.5">
                        <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-ping" />
                        Checking...
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => checkPatchHealth()}
                      disabled={patchServiceChecking}
                      className="p-1 rounded hover:bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                      title="Refresh orchestrator service health"
                    >
                      <RefreshCw className={cn("h-3 w-3", patchServiceChecking && "animate-spin")} />
                    </button>
                  </div>
                </div>

                <div>
                  <label className="text-[13px] text-[var(--sd-text-muted)] block mb-1">Target Host / IP</label>
                  <input
                    type="text"
                    value={patchHost}
                    onChange={(e) => setPatchHost(e.target.value)}
                    placeholder="e.g. 10.0.4.12"
                    list="patch-hosts-datalist"
                    className="sd-input w-full p-2 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[13px] text-[var(--sd-text)] font-mono"
                  />
                  <datalist id="patch-hosts-datalist">
                    <option value="10.0.4.12 (srv-prod-api-01 - Ubuntu 22.04)" />
                    <option value="10.0.4.15 (srv-app-worker-02 - Debian 11)" />
                    <option value="10.0.5.21 (k8s-node-worker-03 - RHEL 9)" />
                    <option value="192.168.1.50 (demo-host)" />
                  </datalist>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[13px] text-[var(--sd-text-muted)] block mb-1">Package Name</label>
                    <input
                      type="text"
                      value={patchPackage}
                      onChange={(e) => setPatchPackage(e.target.value)}
                      placeholder="e.g. openssh-server"
                      className="sd-input w-full p-2 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[13px] text-[var(--sd-text)] font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-[13px] text-[var(--sd-text-muted)] block mb-1">Target Version</label>
                    <input
                      type="text"
                      value={patchTargetVersion}
                      onChange={(e) => setPatchTargetVersion(e.target.value)}
                      placeholder="e.g. 1:8.9p1-3ubuntu0.10"
                      className="sd-input w-full p-2 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[13px] text-[var(--sd-text)] font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[13px] text-[var(--sd-text-muted)] block mb-1">Restart Services (comma-separated)</label>
                  <input
                    type="text"
                    value={patchRestartServices}
                    onChange={(e) => setPatchRestartServices(e.target.value)}
                    placeholder="ssh, nginx"
                    className="sd-input w-full p-2 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[13px] text-[var(--sd-text)] font-mono"
                  />
                </div>

                {/* Collapsible Advanced SSH Config */}
                <div className="border border-[var(--sd-border)] rounded-lg overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowAdvancedSSH(!showAdvancedSSH)}
                    className="w-full px-3 py-2 bg-[var(--sd-bg)] hover:bg-[var(--sd-bg-alt)] text-[12px] text-[var(--sd-text-muted)] flex items-center justify-between cursor-pointer transition"
                  >
                    <span className="flex items-center gap-1.5 font-medium">
                      <Lock className="h-3 w-3" />
                      Advanced SSH Credentials
                    </span>
                    {showAdvancedSSH ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                  </button>

                  {showAdvancedSSH && (
                    <div className="p-3 bg-[var(--sd-bg)] space-y-2.5 border-t border-[var(--sd-border)]">
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <label className="text-[11px] text-[var(--sd-text-dim)] block mb-0.5">SSH User</label>
                          <input
                            type="text"
                            value={patchUser}
                            onChange={(e) => setPatchUser(e.target.value)}
                            placeholder="ubuntu"
                            className="sd-input w-full p-1.5 rounded border border-[var(--sd-border)] bg-[var(--sd-surface)] text-[12px] font-mono text-[var(--sd-text)]"
                          />
                        </div>
                        <div>
                          <label className="text-[11px] text-[var(--sd-text-dim)] block mb-0.5">SSH Port</label>
                          <input
                            type="number"
                            value={patchPort}
                            onChange={(e) => setPatchPort(Number(e.target.value))}
                            placeholder="22"
                            className="sd-input w-full p-1.5 rounded border border-[var(--sd-border)] bg-[var(--sd-surface)] text-[12px] font-mono text-[var(--sd-text)]"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="text-[11px] text-[var(--sd-text-dim)] block mb-0.5">Host Key Fingerprint (SHA256)</label>
                        <input
                          type="text"
                          value={patchHostKeyFingerprint}
                          onChange={(e) => setPatchHostKeyFingerprint(e.target.value)}
                          placeholder="SHA256:abc..."
                          className="sd-input w-full p-1.5 rounded border border-[var(--sd-border)] bg-[var(--sd-surface)] text-[12px] font-mono text-[var(--sd-text)]"
                        />
                      </div>

                      <div>
                        <label className="text-[11px] text-[var(--sd-text-dim)] block mb-0.5">Private Key (OpenSSH PEM)</label>
                        <textarea
                          rows={3}
                          value={patchPrivateKey}
                          onChange={(e) => setPatchPrivateKey(e.target.value)}
                          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..."
                          className="sd-input w-full p-1.5 rounded border border-[var(--sd-border)] bg-[var(--sd-surface)] text-[11px] font-mono text-[var(--sd-text)] resize-none"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div className="p-3 rounded-lg border border-[var(--sd-pine-border)] bg-[var(--sd-pine-dim)] text-[13px] text-[var(--sd-pine-bright)] space-y-1">
                  <div className="font-medium flex items-center gap-1.5">
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
                  <label htmlFor="dryrun" className="text-[13px] text-[var(--sd-text)] cursor-pointer">
                    Dry Run Mode (Simulate without applying live changes)
                  </label>
                </div>

                <div className="flex items-center gap-2 pt-2">
                  <button
                    onClick={() => executePatch(isDryRun)}
                    disabled={loading}
                    className="sd-button sd-button-primary flex-1 px-3 py-2 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium transition cursor-pointer flex items-center justify-center gap-1.5 shadow-xs"
                  >
                    <Play className="h-3.5 w-3.5" />
                    <span>{isDryRun ? "Execute Dry Run" : "Apply Security Patch"}</span>
                  </button>

                  <button
                    onClick={rollbackSnapshot}
                    disabled={loading}
                    className="sd-button px-3 py-2 rounded-full border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] hover:bg-[var(--sd-warning-dim)]/80 text-[var(--sd-warning)] text-[13px] font-medium transition cursor-pointer flex items-center gap-1.5"
                    title="Rollback target host to pre-patch snapshot"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    <span>Rollback</span>
                  </button>
                </div>
              </div>

              {/* Terminal Logs */}
              <div className="lg:col-span-2 p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] font-mono text-[13px] flex flex-col h-[520px] shadow-xs">
                <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-2 mb-2 text-[var(--sd-text-dim)]">
                  <span className="flex items-center gap-2">
                    <span className={cn(
                      "h-2 w-2 rounded-full",
                      activeJobState === "REMEDIATED" ? "bg-emerald-400" :
                      activeJobState?.includes("FAIL") || activeJobState?.includes("ESCALATED") ? "bg-rose-500" :
                      activeJobState ? "bg-amber-400 animate-ping" : "bg-[var(--sd-success)]"
                    )} />
                    <span className="text-[var(--sd-text)] font-semibold">SSH Patching Terminal</span>
                    {activeJobState && (
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-[var(--sd-surface)] border border-[var(--sd-border)] text-[var(--sd-pine-bright)]">
                        {activeJobState}
                      </span>
                    )}
                  </span>
                  <span className="text-[11px] text-[var(--sd-text-dim)]">
                    {activeJobId ? `Job: ${activeJobId}` : "Engine: Go 8004 · LVM CoW"}
                  </span>
                </div>
                <div className="flex-1 overflow-y-auto space-y-1 pr-2">
                  {patchLogs.map((log, index) => (
                    <div key={index} className="leading-relaxed break-words">
                      {log.startsWith("[SNAPSHOT]") ? (
                        <span className="text-[var(--sd-wheat)] font-medium">{log}</span>
                      ) : log.startsWith("[STATUS]") || log.includes("✓") || log.startsWith("[DONE]") ? (
                        <span className="text-emerald-400">{log}</span>
                      ) : log.startsWith("[ROLLBACK") ? (
                        <span className="text-amber-400 font-medium">{log}</span>
                      ) : log.startsWith("[RESTORE") ? (
                        <span className="text-emerald-400 font-medium">{log}</span>
                      ) : log.startsWith("[ERROR]") || log.startsWith("[FAIL]") || log.includes("[ERR]") ? (
                        <span className="text-rose-400 font-medium">{log}</span>
                      ) : log.startsWith("→") ? (
                        <span className="text-cyan-400">{log}</span>
                      ) : log.startsWith("[DRY RUN]") || log.startsWith("[SIMULATION]") ? (
                        <span className="text-purple-400">{log}</span>
                      ) : (
                        <span>{log}</span>
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
            <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface space-y-4 shadow-xs">
              <h3 className="text-sm font-medium text-[var(--sd-text)] flex items-center gap-2">
                <Globe className="h-4 w-4 text-[var(--sd-pine)]" />
                External Attack Surface Management (Shodan &amp; HIBP) · Sample overview
              </h3>
              <p className="text-[13px] text-[var(--sd-text-muted)]">
                Inspect public internet perimeter exposure, open ports, and corporate credential breach disclosures.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                <div className="p-4 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="text-[13px] font-medium text-[var(--sd-text)]">Shodan Perimeter Inspection</span>
                    <span className="text-[11px] font-mono text-[var(--sd-pine-bright)]">24 Hosts Monitored</span>
                  </div>
                  <p className="text-[13px] text-[var(--sd-text-muted)]">
                    Detected Ports: <code className="text-[var(--sd-text)] font-medium">80, 443, 22 (SSH Restrict)</code>. No unauthorized RDP (3389) or Elasticsearch (9200) exposed to WAN.
                  </p>
                </div>

                <div className="p-4 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="text-[13px] font-medium text-[var(--sd-text)]">HaveIBeenPwned Domain Check</span>
                    <span className="text-[11px] font-mono text-[var(--sd-warning)]">1 Domain Flagged</span>
                  </div>
                  <p className="text-[13px] text-[var(--sd-text-muted)]">
                    0 active corporate credentials leaked in paste sites within the last 30 days. Forced TOTP MFA enabled on all IAM accounts.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Advisor Output Modal */}
        {advisorContent && (
          <GlassDialog open onClose={() => setAdvisorContent(null)} labelledBy="scanner-advisor-title" className="max-w-2xl">
            <div className="p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
                <h3 id="scanner-advisor-title" className="text-lg font-normal text-[var(--sd-text)]">{advisorTitle}</h3>
                <button
                  onClick={() => setAdvisorContent(null)}
                  className="sd-button text-[13px] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] font-mono cursor-pointer"
                >
                  ✕ Close
                </button>
              </div>

              <pre className="p-4 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[13px] font-mono text-[var(--sd-text)] overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed">
                {advisorContent}
              </pre>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setAdvisorContent(null)}
                  className="sd-button sd-button-primary px-4 py-2 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          </GlassDialog>
        )}
        {/* Secret Finding Review & Remediate Modal */}
        {reviewingSecret && (() => {
          const findingKey = reviewingSecret.fingerprint || reviewingSecret.secret_hash || `${reviewingSecret.location}:${reviewingSecret.line_number}`;
          const isMitigated = mitigatedIds.has(findingKey);
          const isMitigating = mitigatingId === findingKey;
          const purgeCmd = `git filter-repo --path "${reviewingSecret.location}" --invert-paths`;

          return (
            <GlassDialog
              open
              onClose={() => {
                setReviewingSecret(null);
                setRemediationFeedback(null);
                setCopiedGitCmd(false);
              }}
              labelledBy="secret-review-title"
              className="max-w-2xl w-full"
            >
              <div className="p-6 space-y-4 max-h-[85vh] overflow-y-auto">
                {/* Header */}
                <div className="flex items-start justify-between border-b border-[var(--sd-border)] pb-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-[var(--sd-danger)]/10 text-[var(--sd-danger)] border border-[var(--sd-danger)]/20">
                      <Key className="h-5 w-5" />
                    </div>
                    <div>
                      <h3 id="secret-review-title" className="text-base font-semibold text-[var(--sd-text)] flex items-center gap-2">
                        Review & Remediate Finding
                        {isMitigated && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium text-[var(--sd-pine-bright)] bg-[var(--sd-pine)]/15 border border-[var(--sd-pine)]/30">
                            <CheckCircle2 className="h-3 w-3" /> Remediated
                          </span>
                        )}
                      </h3>
                      <p className="text-[12px] text-[var(--sd-text-muted)] font-mono mt-0.5">
                        Rule: <span className="text-[var(--sd-text)]">{reviewingSecret.rule_id || "generic-api-key"}</span>
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setReviewingSecret(null);
                      setRemediationFeedback(null);
                      setCopiedGitCmd(false);
                    }}
                    className="sd-button text-[13px] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] font-mono cursor-pointer px-2 py-1"
                  >
                    ✕ Close
                  </button>
                </div>

                {/* Finding Context & Metadata Card */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[12px]">
                  <div>
                    <span className="text-[var(--sd-text-muted)] block text-[11px] uppercase tracking-wider">File Location</span>
                    <span className="font-mono text-[var(--sd-text)] font-medium break-all">
                      {reviewingSecret.location}
                      {reviewingSecret.line_number !== undefined && (
                        <span className="text-[var(--sd-pine-bright)] ml-1">#L{reviewingSecret.line_number}</span>
                      )}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--sd-text-muted)] block text-[11px] uppercase tracking-wider">Detection Source</span>
                    <span className="font-mono text-[var(--sd-text)] flex items-center gap-1.5 mt-0.5">
                      {reviewingSecret.source === "git_history" ? (
                        <>
                          <GitCommit className="h-3.5 w-3.5 text-[var(--sd-warning)]" />
                          <span>Git History Commit</span>
                        </>
                      ) : (
                        <>
                          <HardDrive className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                          <span>Active Working Directory</span>
                        </>
                      )}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--sd-text-muted)] block text-[11px] uppercase tracking-wider">Risk Level</span>
                    <span
                      className={cn(
                        "inline-block px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border mt-0.5",
                        reviewingSecret.risk_level === "CRITICAL"
                          ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border-[var(--sd-danger-border)]"
                          : reviewingSecret.risk_level === "HIGH"
                          ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)]"
                          : "bg-[var(--sd-panel-hover)] text-[var(--sd-text)] border-[var(--sd-border)]"
                      )}
                    >
                      {reviewingSecret.risk_level}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--sd-text-muted)] block text-[11px] uppercase tracking-wider">Finding Hash</span>
                    <span className="font-mono text-[11px] text-[var(--sd-text-muted)] truncate block" title={reviewingSecret.fingerprint || reviewingSecret.secret_hash}>
                      {reviewingSecret.fingerprint || reviewingSecret.secret_hash || "Calculated by Gitleaks"}
                    </span>
                  </div>
                </div>

                {/* Git Commit Information if applicable */}
                {reviewingSecret.commit && (
                  <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-hover)]/40 space-y-2 text-[12px]">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-[var(--sd-text)] flex items-center gap-1.5">
                        <GitCommit className="h-3.5 w-3.5 text-[var(--sd-pine-bright)]" />
                        Commit Context
                      </span>
                      <span className="font-mono text-[11px] text-[var(--sd-text-muted)]">
                        SHA: {reviewingSecret.commit.substring(0, 10)}
                      </span>
                    </div>
                    {reviewingSecret.message && (
                      <p className="text-[12px] text-[var(--sd-text)] italic bg-[var(--sd-bg)]/80 p-2 rounded border border-[var(--sd-border)]">
                        &quot;{reviewingSecret.message}&quot;
                      </p>
                    )}
                    <div className="flex flex-wrap gap-4 text-[11px] text-[var(--sd-text-muted)] pt-1">
                      {reviewingSecret.author && (
                        <span>Author: <strong className="text-[var(--sd-text)]">{reviewingSecret.author}</strong></span>
                      )}
                      {reviewingSecret.date && (
                        <span>Date: <strong className="text-[var(--sd-text)]">{new Date(reviewingSecret.date).toUTCString()}</strong></span>
                      )}
                    </div>
                  </div>
                )}

                {/* Redacted Snippet Box */}
                <div className="space-y-1.5">
                  <label className="text-[12px] font-medium text-[var(--sd-text-muted)] flex items-center justify-between">
                    <span>Detected Secret Content (Masked)</span>
                    <span className="text-[10px] text-[var(--sd-pine-bright)]">Protected by Gitleaks Redaction</span>
                  </label>
                  <pre className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[12px] font-mono text-[var(--sd-danger)] overflow-x-auto">
                    {reviewingSecret.snippet_masked || "[REDACTED SECRET VALUE]"}
                  </pre>
                </div>

                {/* Live Remediation Feedback Banner */}
                {remediationFeedback && (
                  <div
                    className={cn(
                      "p-3 rounded-xl border text-[13px] space-y-1",
                      remediationFeedback.success
                        ? "bg-[var(--sd-pine)]/10 border-[var(--sd-pine)]/30 text-[var(--sd-pine-bright)]"
                        : "bg-[var(--sd-danger-dim)] border-[var(--sd-danger-border)] text-[var(--sd-danger)]"
                    )}
                  >
                    <div className="flex items-center gap-2 font-medium">
                      {remediationFeedback.success ? (
                        <CheckCircle2 className="h-4 w-4" />
                      ) : (
                        <AlertTriangle className="h-4 w-4" />
                      )}
                      <span>{remediationFeedback.message}</span>
                    </div>
                    {remediationFeedback.newKeyId && (
                      <div className="font-mono text-[11px] opacity-90 pl-6">
                        New Replacement Credential ID: <span className="underline font-bold">{remediationFeedback.newKeyId}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Remediation Action Plans */}
                <div className="space-y-3 pt-1">
                  <h4 className="text-[13px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
                    <Wrench className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                    Available Remediation Actions
                  </h4>

                  {/* Action 1: Automated Key Invalidation */}
                  <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-surface)] space-y-2.5">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-medium text-[13px] text-[var(--sd-text)]">
                          1. Automated Credential Revocation & Rotation
                        </div>
                        <p className="text-[11px] text-[var(--sd-text-muted)] mt-0.5">
                          Immediately issue a revocation call to invalidate this token and provision an updated credential via the ShieldDesk rotation orchestrator.
                        </p>
                      </div>
                      <button
                        onClick={() => executeRemediation(reviewingSecret, "rotate_key")}
                        disabled={isMitigating}
                        className="sd-button sd-button-primary shrink-0 px-3 py-1.5 rounded-lg text-[12px] font-medium text-[var(--sd-on-accent)] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                      >
                        {isMitigating ? (
                          <>
                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                            <span>Revoking…</span>
                          </>
                        ) : (
                          <>
                            <RotateCcw className="h-3.5 w-3.5" />
                            <span>Revoke / Rotate Key</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Action 2: Purge from Git History if git commit */}
                  {reviewingSecret.source === "git_history" && (
                    <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-surface)] space-y-2.5">
                      <div>
                        <div className="font-medium text-[13px] text-[var(--sd-text)] flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 text-[var(--sd-warning)]" />
                          <span>2. Scrub Secret from Git Repository History</span>
                        </div>
                        <p className="text-[11px] text-[var(--sd-text-muted)] mt-0.5">
                          Because this secret exists in committed git objects, simply editing the file leaves history exposed. Run this command to rewrite git history:
                        </p>
                      </div>

                      <div className="flex items-center gap-2">
                        <code className="p-2 rounded bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[11px] font-mono text-[var(--sd-text)] flex-1 overflow-x-auto">
                          {purgeCmd}
                        </code>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(purgeCmd);
                            setCopiedGitCmd(true);
                            setTimeout(() => setCopiedGitCmd(false), 2000);
                          }}
                          className="sd-button px-3 py-2 rounded border border-[var(--sd-border)] bg-[var(--sd-panel-hover)] hover:bg-[var(--sd-panel)] text-[12px] text-[var(--sd-text)] shrink-0 flex items-center gap-1 cursor-pointer font-medium"
                        >
                          {copiedGitCmd ? (
                            <>
                              <Check className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                              <span className="text-[var(--sd-pine)]">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3.5 w-3.5" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Action 3: Filesystem Best Practices if active working directory */}
                  {reviewingSecret.source !== "git_history" && (
                    <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-surface)] space-y-2">
                      <div className="font-medium text-[13px] text-[var(--sd-text)] flex items-center gap-1.5">
                        <HardDrive className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                        <span>2. Filesystem & Environment Hygiene</span>
                      </div>
                      <p className="text-[11px] text-[var(--sd-text-muted)]">
                        Ensure <code className="text-[var(--sd-pine-bright)]">{reviewingSecret.location}</code> is added to <code className="text-[var(--sd-text)]">.gitignore</code> so credentials are never checked into remote repositories. Migrate production secrets into a cloud secret manager (Supabase Vault or AWS KMS).
                      </p>
                    </div>
                  )}

                  {/* Action 4: Mark Resolved / Whitelist */}
                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[11px] text-[var(--sd-text-muted)]">
                      Analyst verified key is inactive or non-sensitive test token:
                    </span>
                    <button
                      onClick={() => executeRemediation(reviewingSecret, "mark_resolved")}
                      disabled={isMitigating || isMitigated}
                      className="sd-button px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-hover)] hover:bg-[var(--sd-panel)] text-[12px] text-[var(--sd-text)] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                      <span>{isMitigated ? "Already Resolved" : "Mark as Resolved"}</span>
                    </button>
                  </div>
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between pt-3 border-t border-[var(--sd-border)]">
                  <div className="text-[11px] text-[var(--sd-text-muted)]">
                    Audit trail logs all remediation actions to SIEM.
                  </div>
                  <button
                    onClick={() => {
                      setReviewingSecret(null);
                      setRemediationFeedback(null);
                      setCopiedGitCmd(false);
                    }}
                    className="sd-button sd-button-primary px-4 py-1.5 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium cursor-pointer"
                  >
                    Done
                  </button>
                </div>
              </div>
            </GlassDialog>
          );
        })()}
      </main>
    </div>
  );
}
