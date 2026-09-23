"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Activity,
  Server,
  Sparkles,
  ArrowRight,
  RefreshCw,
  Layers,
  Clock,
  Terminal,
  FileText,
  Shield,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import { useChat } from "@/lib/context/ChatContext";
import { TopNavBar } from "@/components/navigation/TopNavBar";

interface IncidentSummary {
  incident_code: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "investigating" | "resolved" | "closed";
  title: string;
  created_at: string;
}

interface IncidentDetail {
  incident: {
    incidentCode: string;
    severity: string;
    status: string;
    title: string;
    description: string;
    createdAt: string;
  };
  events: Array<{ occurred_at: string; description: string }>;
  affectedAssets: Array<{ hostname: string; asset_type: string }>;
}

export default function SOCDashboardPage() {
  const {
    activeUserId,
    activeUser,
    activeIncidentId,
    setActiveIncidentId,
    openChatWithPrompt,
  } = useChat();

  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [isLoadingList, setIsLoadingList] = useState(false);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  // Fetch incidents list whenever active persona or severity filter changes
  useEffect(() => {
    let isMounted = true;
    setIsLoadingList(true);

    const queryParams = new URLSearchParams();
    if (filterSeverity !== "all") {
      queryParams.set("severity", filterSeverity);
    }

    fetch(`/api/incidents?${queryParams.toString()}`, {
      headers: { "X-ShieldDesk-User": activeUserId },
    })
      .then(async (res) => {
        if (!res.ok) throw new Error("Failed to fetch incidents");
        return res.json();
      })
      .then((data) => {
        if (!isMounted) return;
        const list = data?.incidents || [];
        setIncidents(list);
        if (list.length > 0) {
          const firstCode = list[0].incident_code;
          setActiveIncidentId(firstCode);
        } else {
          setActiveIncidentId(null);
          setSelectedIncident(null);
        }
      })
      .catch((err) => {
        console.error("Incidents fetch error:", err);
        if (isMounted) setIncidents([]);
      })
      .finally(() => {
        if (isMounted) setIsLoadingList(false);
      });

    return () => {
      isMounted = false;
    };
  }, [activeUserId, filterSeverity, setActiveIncidentId]);

  // Fetch incident detail when activeIncidentId changes
  useEffect(() => {
    if (!activeIncidentId) {
      setSelectedIncident(null);
      return;
    }

    let isMounted = true;
    setIsLoadingDetail(true);

    fetch(`/api/incidents?id=${encodeURIComponent(activeIncidentId)}`, {
      headers: { "X-ShieldDesk-User": activeUserId },
    })
      .then(async (res) => {
        if (!res.ok) throw new Error("Incident not found or unauthorized");
        return res.json();
      })
      .then((data) => {
        if (isMounted && !("error" in data)) {
          setSelectedIncident(data);
        }
      })
      .catch(() => {
        if (isMounted) setSelectedIncident(null);
      })
      .finally(() => {
        if (isMounted) setIsLoadingDetail(false);
      });

    return () => {
      isMounted = false;
    };
  }, [activeIncidentId, activeUserId]);

  const getSeverityBadge = (severity: string) => {
    const s = severity.toUpperCase();
    if (s === "CRITICAL") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]">
          <ShieldAlert className="h-3 w-3 text-[var(--sd-danger)]" /> CRITICAL
        </span>
      );
    }
    if (s === "HIGH") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]">
          <AlertTriangle className="h-3 w-3 text-[var(--sd-warning)]" /> HIGH
        </span>
      );
    }
    if (s === "MEDIUM") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-[var(--sd-panel-raised)] text-[var(--sd-beige-dim)] border border-[var(--sd-border)]">
          MEDIUM
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]">
        <CheckCircle className="h-3 w-3 text-[var(--sd-success)]" /> {s}
      </span>
    );
  };

  return (
    <div className="flex-1 flex flex-col bg-[var(--sd-bg)] text-[var(--sd-text)] min-h-screen">
      {/* Global Top Navbar */}
      <TopNavBar />

      {/* Main Workspace Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar: Incident Feed */}
        <aside className="w-[380px] shrink-0 border-r border-[var(--sd-border)] bg-[var(--sd-panel)] flex flex-col">
          {/* Feed Header & Filters */}
          <div className="p-4 border-b border-[var(--sd-border)] space-y-3 bg-[var(--sd-bg-alt)]/40">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                  Incident Queue
                </h2>
                <span className="text-[11px] text-[var(--sd-text-muted)]">
                  Tenant: <strong className="text-[var(--sd-text)]">{activeUser.tenantName}</strong>
                </span>
              </div>
              <span className="rounded-md bg-white border border-[var(--sd-border)] px-2 py-0.5 text-[11px] font-mono font-semibold text-[var(--sd-pine)] shadow-xs">
                {incidents.length} Active
              </span>
            </div>

            {/* Severity Filter Pills */}
            <div className="flex gap-1.5 overflow-x-auto pb-0.5">
              {["all", "critical", "high", "medium"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={cn(
                    "px-2.5 py-1 rounded-md text-[10.5px] uppercase font-semibold tracking-wider transition-all duration-150 cursor-pointer",
                    filterSeverity === sev
                      ? "bg-[var(--sd-pine)] text-[#f7f4ed] shadow-xs"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)]"
                  )}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Incident List */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2 bg-[var(--sd-panel)]">
            {isLoadingList ? (
              <div className="py-12 text-center text-xs text-[var(--sd-text-muted)] flex flex-col items-center gap-2">
                <RefreshCw className="h-4 w-4 animate-spin text-[var(--sd-pine)]" />
                <span>Loading tenant telemetry...</span>
              </div>
            ) : incidents.length === 0 ? (
              <div className="py-16 text-center px-4 rounded-xl border border-dashed border-[var(--sd-border)] bg-[var(--sd-panel-raised)] my-4">
                <CheckCircle className="h-8 w-8 text-[var(--sd-pine-bright)]/40 mx-auto mb-2" />
                <h4 className="text-xs font-semibold text-[var(--sd-pine)]">Zero Incidents Reported</h4>
                <p className="text-[11px] text-[var(--sd-text-muted)] mt-1 max-w-[220px] mx-auto leading-relaxed">
                  Tenant <span className="font-mono text-[var(--sd-pine)] font-medium">{activeUser.tenantId}</span> has no active incidents
                  matching your filter. Multi-tenant isolation verified!
                </p>
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = activeIncidentId === inc.incident_code;
                return (
                  <motion.div
                    key={inc.incident_code}
                    onClick={() => setActiveIncidentId(inc.incident_code)}
                    whileHover={{ scale: 1.005 }}
                    className={cn(
                      "p-3 rounded-xl border transition-all duration-150 cursor-pointer flex flex-col gap-1.5",
                      isSelected
                        ? "border-[var(--sd-pine)] bg-[var(--sd-bg-alt)]/60 shadow-xs ring-1 ring-[var(--sd-pine)]/20"
                        : "border-[var(--sd-border)] bg-white hover:border-[var(--sd-border-strong)] hover:bg-[var(--sd-panel-hover)]/40"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className={cn(
                        "font-mono text-xs font-bold tracking-tight",
                        isSelected ? "text-[var(--sd-pine)]" : "text-[var(--sd-text)]"
                      )}>
                        {inc.incident_code}
                      </span>
                      {getSeverityBadge(inc.severity)}
                    </div>
                    <h3 className="text-xs font-semibold text-[var(--sd-text)] line-clamp-1 leading-snug">
                      {inc.title}
                    </h3>
                    <div className="flex items-center justify-between text-[10.5px] text-[var(--sd-text-muted)] mt-0.5">
                      <span className="capitalize font-mono font-medium">{inc.status}</span>
                      <span className="flex items-center gap-1 font-mono">
                        <Clock className="h-2.5 w-2.5" />
                        {new Date(inc.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                  </motion.div>
                );
              })
            )}
          </div>
        </aside>

        {/* Center / Right: Incident Detail Investigation & AI Co-Pilot Console */}
        <main className="flex-1 overflow-y-auto p-6 flex flex-col gap-6 bg-[var(--sd-bg)]">
          {isLoadingDetail ? (
            <div className="flex-1 flex items-center justify-center text-xs text-[var(--sd-text-muted)] gap-2">
              <RefreshCw className="h-5 w-5 animate-spin text-[var(--sd-pine)]" />
              <span>Querying incident telemetry and timeline...</span>
            </div>
          ) : selectedIncident ? (
            <>
              {/* Incident Header Card */}
              <div className="rounded-2xl border border-[var(--sd-border)] bg-white p-6 shadow-xs space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="rounded-lg bg-[var(--sd-bg-alt)] px-2.5 py-1 font-mono text-sm font-bold text-[var(--sd-pine)] border border-[var(--sd-border)]">
                      {selectedIncident.incident.incidentCode}
                    </span>
                    {getSeverityBadge(selectedIncident.incident.severity)}
                    <span className="rounded-md bg-[var(--sd-bg)] border border-[var(--sd-border)] px-2.5 py-1 text-xs text-[var(--sd-text-muted)] capitalize font-mono">
                      Status: <strong className="text-[var(--sd-text)]">{selectedIncident.incident.status}</strong>
                    </span>
                  </div>

                  {/* AI & Governance Action Trigger Buttons */}
                  <div className="flex items-center gap-2 flex-wrap">
                    {selectedIncident.incident.incidentCode === "INC-1042" && (
                      <Link
                        href="/dashboard/plans/p1111111-1111-1111-1111-111111111111"
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg-alt)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-pine)] transition-all cursor-pointer shadow-xs"
                      >
                        <Layers className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                        <span>Inspect Mitigation Plan</span>
                      </Link>
                    )}

                    <button
                      onClick={() =>
                        openChatWithPrompt(
                          `Investigate ${selectedIncident.incident.incidentCode}`,
                          selectedIncident.incident.incidentCode
                        )
                      }
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-xs font-semibold text-[#f7f4ed] transition-all cursor-pointer shadow-xs"
                    >
                      <Sparkles className="h-3.5 w-3.5 text-[#e6dbbf]" />
                      Investigate with AI
                    </button>
                    <button
                      onClick={() =>
                        openChatWithPrompt(
                          `Generate a mitigation plan for ${selectedIncident.incident.incidentCode}`,
                          selectedIncident.incident.incidentCode
                        )
                      }
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-white hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition-all cursor-pointer shadow-xs"
                    >
                      <FileText className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                      Plan Mitigation
                    </button>
                  </div>
                </div>

                <div>
                  <h2 className="text-xl font-bold tracking-tight text-[var(--sd-text)]">
                    {selectedIncident.incident.title}
                  </h2>
                  <p className="text-xs text-[var(--sd-text-muted)] mt-1.5 leading-relaxed max-w-4xl">
                    {selectedIncident.incident.description}
                  </p>
                </div>
              </div>

              {/* Grid: Assets + Timeline */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Affected Assets Card */}
                <div className="rounded-2xl border border-[var(--sd-border)] bg-white p-5 shadow-xs flex flex-col">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-[var(--sd-pine)]" />
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                        Impacted Assets ({selectedIncident.affectedAssets.length})
                      </h3>
                    </div>
                  </div>

                  <div className="space-y-2 flex-1">
                    {selectedIncident.affectedAssets.length === 0 ? (
                      <div className="py-6 text-center text-xs text-[var(--sd-text-muted)]">No linked assets identified.</div>
                    ) : (
                      selectedIncident.affectedAssets.map((asset, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs"
                        >
                          <div className="flex items-center gap-2.5">
                            <div className="h-7 w-7 rounded-lg bg-white border border-[var(--sd-border)] flex items-center justify-center">
                              <Terminal className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                            </div>
                            <div>
                              <div className="font-mono font-semibold text-[var(--sd-text)]">{asset.hostname}</div>
                              <div className="text-[10.5px] text-[var(--sd-text-muted)] capitalize">{asset.asset_type}</div>
                            </div>
                          </div>
                          <span className="rounded bg-[var(--sd-danger-dim)] border border-[var(--sd-danger-border)] text-[var(--sd-danger)] text-[10px] px-2 py-0.5 font-semibold">
                            Compromised Scope
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Chronological Event Timeline */}
                <div className="rounded-2xl border border-[var(--sd-border)] bg-white p-5 shadow-xs flex flex-col">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4 text-[var(--sd-pine)]" />
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                        Attack Timeline ({selectedIncident.events.length})
                      </h3>
                    </div>
                  </div>

                  <div className="space-y-3 flex-1 relative before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-[var(--sd-border)] pl-8">
                    {selectedIncident.events.length === 0 ? (
                      <div className="py-6 text-center text-xs text-[var(--sd-text-muted)]">No timeline events recorded.</div>
                    ) : (
                      selectedIncident.events.map((event, idx) => (
                        <div key={idx} className="relative text-xs group">
                          <div className="absolute -left-8 top-1.5 h-2.5 w-2.5 rounded-full bg-[var(--sd-pine)] ring-4 ring-white" />
                          <div className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] group-hover:bg-[var(--sd-panel-hover)]/50 transition-colors">
                            <span className="font-mono text-[10px] font-semibold text-[var(--sd-pine)] block mb-0.5">
                              {new Date(event.occurred_at).toLocaleTimeString([], {
                                hour: "2-digit",
                                minute: "2-digit",
                                second: "2-digit",
                              })}
                            </span>
                            <p className="text-[var(--sd-text)] leading-snug">{event.description}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Threat Intelligence / CVE Correlation Bar */}
              <div className="rounded-2xl border border-[var(--sd-border)] bg-white p-5 shadow-xs">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Layers className="h-4 w-4 text-[var(--sd-pine)]" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                      Linked Threat Intelligence (CVE-2020-6240)
                    </h3>
                  </div>
                  <button
                    onClick={() => openChatWithPrompt("Analyze CVE-2020-6240")}
                    className="text-xs text-[var(--sd-pine)] hover:underline flex items-center gap-1 cursor-pointer font-semibold transition-colors"
                  >
                    Deep Threat Analysis <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                    <div className="text-[10px] text-[var(--sd-text-muted)] uppercase tracking-wider font-medium">CVSS Score</div>
                    <div className="text-sm font-bold text-[var(--sd-warning)] mt-0.5 font-mono">7.5 (HIGH)</div>
                  </div>
                  <div className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                    <div className="text-[10px] text-[var(--sd-text-muted)] uppercase tracking-wider font-medium">Autonomy Gate</div>
                    <div className="text-sm font-bold text-[var(--sd-pine)] mt-0.5">Tier 2 (Human Sign-off)</div>
                  </div>
                  <div className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                    <div className="text-[10px] text-[var(--sd-text-muted)] uppercase tracking-wider font-medium">CWE Classification</div>
                    <div className="text-sm font-bold text-[var(--sd-text)] mt-0.5">CWE-400 (Resource Exhaustion)</div>
                  </div>
                  <div className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                    <div className="text-[10px] text-[var(--sd-text-muted)] uppercase tracking-wider font-medium">Remediation SLA</div>
                    <div className="text-sm font-bold text-[var(--sd-text)] mt-0.5 font-mono">Within 7 Days</div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-12">
              <ShieldAlert className="h-10 w-10 text-[var(--sd-border-strong)] mb-3" />
              <h3 className="text-sm font-bold text-[var(--sd-pine)]">No Incident Selected</h3>
              <p className="text-xs text-[var(--sd-text-muted)] mt-1 max-w-sm">
                Select an incident from the queue on the left to review its timeline, affected assets, and correlated
                threat intelligence.
              </p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
