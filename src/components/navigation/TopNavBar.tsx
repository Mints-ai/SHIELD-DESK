"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, Sparkles, ChevronDown, Menu, X, Activity,
  Database,
  Cpu,
  Lock,
  Layers,
  CheckSquare,
  Server,
  FileCheck2,
  FileText,
  BarChart3,
  LogIn,
  Scan,
  Flame,
  Cloud,
  Bot,
} from "lucide-react";
import { useChat, DEV_USERS, type DevUserId } from "@/lib/context/ChatContext";
import { ApprovalModal } from "@/components/governance/ApprovalModal";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

export function TopNavBar() {
  const pathname = usePathname();
  const { activeUserId, activeUser, setActiveUserId, setIsChatOpen } = useChat();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const navigationToggleRef = useRef<HTMLButtonElement>(null);
  const [healthLoaded, setHealthLoaded] = useState(false);

  const [healthStatus, setHealthStatus] = useState<{
    database: boolean;
    ollama: boolean;
    supabase: boolean;
    pythonAiEngine: boolean;
  }>({ database: false, ollama: false, supabase: false, pythonAiEngine: false });

  const [envMeta, setEnvMeta] = useState<{
    environment: string;
    isProduction: boolean;
    isDemoMode: boolean;
    failClosed: boolean;
    devPersonasAllowed: boolean;
  }>({
    environment: "development",
    isProduction: false,
    isDemoMode: true,
    failClosed: false,
    devPersonasAllowed: true,
  });

  const [pendingTokens, setPendingTokens] = useState<ApprovalTokenRecord[]>([]);
  const [activeModalToken, setActiveModalToken] = useState<ApprovalTokenRecord | null>(null);
  const [activeModalIndex, setActiveModalIndex] = useState(0);
  const [isApprovalModalOpen, setIsApprovalModalOpen] = useState(false);

  useEffect(() => {
    fetch("/api/health")
      .then((res) => res.json())
      .then((data) => {
        setHealthStatus({
          database: Boolean(data?.database?.connected),
          ollama: Boolean(data?.ollama?.reachable),
          supabase: Boolean(data?.supabase?.connected),
          pythonAiEngine: Boolean(data?.pythonAiEngine?.reachable),
        });
        if (data?.environment) {
          setEnvMeta(data.environment);
        }
      })
      .catch(() => {
        setHealthStatus({ database: false, ollama: false, supabase: false, pythonAiEngine: false });
      })
      .finally(() => setHealthLoaded(true));
  }, []);

  const fetchApprovals = useCallback(() => {
    fetch("/api/approvals?status=pending", {
      headers: { "X-ShieldDesk-User": activeUserId },
    })
      .then((res) => res.json())
      .then((data) => {
        setPendingTokens(data?.tokens || []);
      })
      .catch(() => {
        setPendingTokens([]);
      });
  }, [activeUserId]);

  useEffect(() => {
    fetchApprovals();

    const handleSync = () => {
      fetchApprovals();
    };
    window.addEventListener("shielddesk:approvals-changed", handleSync);
    const interval = setInterval(fetchApprovals, 4000);

    return () => {
      window.removeEventListener("shielddesk:approvals-changed", handleSync);
      clearInterval(interval);
    };
  }, [fetchApprovals]);

  const navLinks = [
    { href: "/", label: "Incident Queue", icon: Layers },
    { href: "/dashboard/plans", label: "Mitigation Plans", icon: FileText },
    { href: "/dashboard/tasks", label: "Task Board", icon: CheckSquare },
    { href: "/dashboard/fleet", label: "Fleet & Host", icon: Server },
    { href: "/dashboard/scanner", label: "Security Scanner", icon: Scan },
    { href: "/dashboard/threats", label: "Threat Engine", icon: Flame },
    { href: "/dashboard/compliance", label: "ISO 27001 Audit", icon: FileCheck2 },
    { href: "/dashboard/risk-scorecard", label: "Risk Scorecard", icon: BarChart3 },
  ];

  const services = [
    { label: "Database", connected: healthStatus.database, icon: Database },
    { label: "Supabase", connected: healthStatus.supabase, icon: Cloud },
    { label: "Local assistant", connected: healthStatus.ollama, icon: Cpu },
    { label: "Threat engine", connected: healthStatus.pythonAiEngine, icon: Bot },
  ];
  const connectedCount = services.filter((service) => service.connected).length;

  return (
    <>
      <header className="sd-app-header">
        <button ref={navigationToggleRef} className="sd-button sd-mobile-nav-toggle !px-2" aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileNavOpen} aria-controls="workspace-navigation" onClick={() => setMobileNavOpen(!mobileNavOpen)}>
          {mobileNavOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
        <Link href="/" className="sd-mobile-brand" aria-label="ShieldDesk home"><Shield size={20} strokeWidth={1.5} aria-hidden="true" /><span>ShieldDesk</span></Link>
        <button className="sd-button sd-header-search" onClick={() => setIsChatOpen(true)} aria-label="Open ShieldDesk AI assistant">
          <Sparkles size={17} className="text-[var(--sd-wheat)]" /><span>Ask about an incident, vulnerability, or response…</span>
        </button>
        <div className="sd-header-controls">
          <details
            className="sd-health-menu"
            onBlur={(event) => {
              const menu = event.currentTarget;
              if (!menu.contains(event.relatedTarget as Node | null)) {
                window.requestAnimationFrame(() => {
                  if (!menu.contains(document.activeElement)) menu.open = false;
                });
              }
            }}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.currentTarget.open = false;
                event.currentTarget.querySelector("summary")?.focus();
              }
            }}
          >
            <summary className="sd-health-trigger"><Activity size={18} className="text-[var(--sd-wheat)]" /><div className="sd-health-caption">System health<p>{healthLoaded ? `${connectedCount} of 4 services connected` : "Checking services…"}</p></div><ChevronDown size={12} /></summary>
            <div className="sd-popover"><p className="sd-eyebrow mb-2">System connections</p>{services.map(({ label, connected, icon: Icon }) => <div key={label} className="sd-health-row"><span><Icon size={14} />{label}</span><span className={connected ? "text-[var(--sd-success)]" : "text-[var(--sd-text-muted)]"}><i className="sd-status-dot" />{healthLoaded ? connected ? "Connected" : "Offline" : "Checking"}</span></div>)}</div>
          </details>
          {activeUser.role !== "analyst" && (

            <button
              className="sd-button !px-3"
              disabled={pendingTokens.length === 0}
              aria-label={`Approvals, ${pendingTokens.length} pending`}
              title={pendingTokens.length > 0 ? "Review pending approvals" : "No pending approvals"}
              onClick={() => {
                if (pendingTokens.length === 0) return;
                setActiveModalIndex(0);
                setActiveModalToken(pendingTokens[0]);
                setIsApprovalModalOpen(true);
              }}
            >
              <Lock size={16} /><span>{pendingTokens.length}</span>
            </button>
          )}
          {envMeta.devPersonasAllowed && <div className="sd-profile"><span className="sd-avatar" aria-hidden="true">{activeUser.label.split(" ").map((word) => word[0]).slice(0,2).join("")}</span><div><select aria-label="Active operator persona" value={activeUserId} onChange={(event) => setActiveUserId(event.target.value as DevUserId)} className="outline-none focus:outline-none focus:ring-0 focus-visible:outline-none border-none shadow-none cursor-pointer bg-transparent" style={{ outline: "none", border: "none", boxShadow: "none" }}>{(Object.keys(DEV_USERS) as DevUserId[]).map((id) => <option key={id} value={id}>{DEV_USERS[id].label}</option>)}</select><p className="sd-profile-caption">{activeUser.tenantName}</p></div></div>}
          <Link href="/login" className="sd-button !px-3" aria-label="Sign in"><LogIn size={16} /><span className="sd-signin-label">Sign in</span></Link>
        </div>
      </header>
      <aside id="workspace-navigation" className="sd-sidebar" data-open={mobileNavOpen} onKeyDown={(event) => { if (event.key === "Escape") { setMobileNavOpen(false); navigationToggleRef.current?.focus(); } }}>
        <Link href="/" className="sd-brand" aria-label="ShieldDesk home"><Shield className="sd-brand-symbol" size={36} strokeWidth={1.2} /><div><div className="sd-brand-name">ShieldDesk</div><div className="sd-brand-caption">Security operations</div></div></Link>
        <nav aria-label="Dashboard"><p className="sd-nav-label">Workspace</p>{navLinks.map(({ href, label, icon: Icon }) => <Link key={href} href={href} onClick={() => setMobileNavOpen(false)} className="sd-nav-link" aria-current={(href === "/" ? pathname === "/" : pathname?.startsWith(href)) ? "page" : undefined}><Icon size={18} strokeWidth={1.5} /><span>{label}</span></Link>)}</nav>
        <div className="sd-sidebar-bottom"><p>Clarity in every signal.<br />Confidence in every action.</p><div className="sd-sidebar-rule" /><span className="sd-sample-label"><i className="sd-status-dot" />{envMeta.isDemoMode ? "Demo environment" : "Live SOC"}</span><div className="sd-sidebar-footnote">{envMeta.isDemoMode ? "Illustrative data · Development workspace" : "Live telemetry · Governed operations"}<br />ShieldDesk · Mints Global</div></div>
      </aside>

      {/* Approval Modal mounted globally */}
      <ApprovalModal
        isOpen={isApprovalModalOpen}
        onClose={() => setIsApprovalModalOpen(false)}
        token={activeModalToken}
        totalCount={pendingTokens.length}
        currentIndex={activeModalIndex}
        onNavigate={(index) => {
          setActiveModalIndex(index);
          setActiveModalToken(pendingTokens[index]);
        }}
        onDecisionSuccess={(updatedToken) => {
          fetchApprovals();
          if (typeof window !== "undefined") {
            window.dispatchEvent(
              new CustomEvent("shielddesk:approvals-changed", {
                detail: { action: updatedToken?.status, token: updatedToken },
              })
            );
          }
        }}
      />
    </>
  );
}
