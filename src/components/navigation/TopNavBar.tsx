"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
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
import { cn } from "@/lib/utils";
import { useChat, DEV_USERS, type DevUserId } from "@/lib/context/ChatContext";
import { ApprovalModal } from "@/components/governance/ApprovalModal";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

export function TopNavBar() {
  const pathname = usePathname();
  const { activeUserId, setActiveUserId } = useChat();

  const [healthStatus, setHealthStatus] = useState<{
    database: boolean;
    ollama: boolean;
    supabase: boolean;
    pythonAiEngine: boolean;
  }>({ database: false, ollama: false, supabase: false, pythonAiEngine: false });

  const [pendingTokens, setPendingTokens] = useState<ApprovalTokenRecord[]>([]);
  const [activeModalToken, setActiveModalToken] = useState<ApprovalTokenRecord | null>(null);
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
      })
      .catch(() => {
        setHealthStatus({ database: false, ollama: false, supabase: false, pythonAiEngine: false });
      });
  }, []);

  const fetchApprovals = () => {
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
  };

  useEffect(() => {
    fetchApprovals();
  }, [activeUserId]);

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

  return (
    <>
      <header className="sticky top-0 z-50 flex min-h-16 items-center justify-between gap-3 border-b border-[var(--sd-border)] bg-[var(--sd-panel)]/95 px-3 py-2.5 shadow-xs backdrop-blur-md sm:px-5">
        {/* Brand & Platform Identifier */}
        <div className="flex min-w-0 items-center gap-3">
          <Link href="/" className="flex items-center gap-3 group cursor-pointer">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-white overflow-hidden shadow-xs group-hover:scale-105 transition-all duration-200 border border-[var(--sd-border)] p-1">
              <img src="/logo.png" alt="ShieldDesk" className="h-full w-full object-contain" />
            </div>
            <div className="hidden min-w-0 md:block">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold tracking-tight text-[var(--sd-text)] font-sans">
                  Shield<span className="text-[#a48858]">Desk</span><span className="text-[9px] text-[#a48858] align-super">™</span>
                </span>
                <span className="rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest bg-[var(--sd-bg)] text-[var(--sd-pine)] border border-[var(--sd-border)] font-mono">
                  Autonomous SOC
                </span>
              </div>
              <p className="text-[10px] text-[var(--sd-text-muted)] font-normal">
                AI-Powered Security Operations · A Product by Mints Global
              </p>
            </div>
          </Link>
        </div>

        {/* Right Section: Approvals + Micro Status + Persona Switcher */}
        <div className="ml-auto flex shrink-0 items-center gap-2 sm:gap-2.5">
          <button
            onClick={() => {
              if (pendingTokens.length === 0) return;
              setActiveModalToken(pendingTokens[0]);
              setIsApprovalModalOpen(true);
            }}
            disabled={pendingTokens.length === 0}
            aria-label={`Approvals${pendingTokens.length > 0 ? `, ${pendingTokens.length} pending` : ""}`}
            className={cn(
              "relative flex h-9 shrink-0 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold shadow-xs transition",
              pendingTokens.length > 0
                ? "border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] hover:bg-[var(--sd-danger-dim)]/80 cursor-pointer"
                : "border-[var(--sd-border)] bg-[var(--sd-bg)] text-[var(--sd-text-muted)] cursor-default"
            )}
            title={pendingTokens.length > 0 ? "Review pending approvals" : "No pending approvals"}
          >
            <Lock className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Approvals</span>
            {pendingTokens.length > 0 && (
              <span className="min-w-4 rounded-full bg-[var(--sd-danger)] px-1 text-center text-[10px] leading-4 text-white">
                {pendingTokens.length}
              </span>
            )}
          </button>

          {/* Micro Health Indicators */}
          <div className="hidden xl:flex items-center gap-3 px-2.5 py-1 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[10.5px]">
            <div className="flex items-center gap-1.5" title="PostgreSQL Database Connection">
              <Database className="h-3 w-3 text-[var(--sd-text-muted)]" />
              <span className="text-[var(--sd-text-muted)] font-medium">DB:</span>
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  healthStatus.database ? "bg-[var(--sd-pine-bright)] shadow-[0_0_6px_var(--sd-pine-bright)]" : "bg-[var(--sd-warning)]"
                )}
              />
            </div>
            <div className="h-3 w-px bg-[var(--sd-border)]" />
            <div className="flex items-center gap-1.5" title="Supabase Cloud Database & Auth">
              <Cloud className="h-3 w-3 text-[var(--sd-text-muted)]" />
              <span className="text-[var(--sd-text-muted)] font-medium">Supabase:</span>
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  healthStatus.supabase ? "bg-[var(--sd-pine-bright)] shadow-[0_0_6px_var(--sd-pine-bright)]" : "bg-[var(--sd-text-dim)]"
                )}
              />
            </div>
            <div className="h-3 w-px bg-[var(--sd-border)]" />
            <div className="flex items-center gap-1.5" title="Local Ollama LLM Connection">
              <Cpu className="h-3 w-3 text-[var(--sd-text-muted)]" />
              <span className="text-[var(--sd-text-muted)] font-medium">Ollama:</span>
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  healthStatus.ollama ? "bg-[var(--sd-pine-bright)] shadow-[0_0_6px_var(--sd-pine-bright)]" : "bg-[var(--sd-text-dim)]"
                )}
              />
            </div>
            <div className="h-3 w-px bg-[var(--sd-border)]" />
            <div className="flex items-center gap-1.5" title="Python CVE & ML Vulnerability Intelligence Engine (Port 8000)">
              <Bot className="h-3 w-3 text-[var(--sd-text-muted)]" />
              <span className="text-[var(--sd-text-muted)] font-medium">Python AI:</span>
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  healthStatus.pythonAiEngine ? "bg-[var(--sd-pine-bright)] shadow-[0_0_6px_var(--sd-pine-bright)]" : "bg-[var(--sd-text-dim)]"
                )}
              />
            </div>
          </div>

          {/* Persona Switcher */}
          <div className="flex items-center gap-1 border border-[var(--sd-border)] bg-[var(--sd-bg)] rounded-lg p-0.5">
            {(Object.keys(DEV_USERS) as DevUserId[]).map((userId) => {
              const u = DEV_USERS[userId];
              const isSelected = activeUserId === userId;
              return (
                <button
                  key={userId}
                  onClick={() => setActiveUserId(userId)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-md px-1.5 py-1 text-xs font-medium transition-all duration-150 cursor-pointer sm:px-2.5",
                    isSelected
                      ? "bg-[var(--sd-pine)] text-[#f7f4ed] shadow-xs font-semibold"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)]"
                  )}
                  title={`${u.label} (${u.tenantName})`}
                >
                  <span
                    className={cn(
                      "h-1.5 w-1.5 rounded-full",
                      userId === "dev-admin"
                        ? "bg-[#9333ea]"
                        : userId === "dev-other"
                          ? "bg-[#d97706]"
                          : "bg-[var(--sd-pine-bright)]"
                    )}
                  />
                  <span className="hidden 2xl:inline">{u.label}</span>
                </button>
              );
            })}
          </div>

          <Link
            href="/login"
            className="flex shrink-0 items-center gap-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] px-2.5 py-1.5 text-xs font-medium text-[var(--sd-text)] shadow-xs transition hover:bg-[var(--sd-panel-hover)] sm:px-3"
            title="Sign In / Operator Identity"
          >
            <LogIn className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
            <span className="hidden sm:inline">Sign In</span>
          </Link>
        </div>
      </header>

      <aside className="sd-dashboard-nav group fixed bottom-0 left-0 top-16 z-40 w-14 overflow-hidden border-r border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs transition-[width] duration-200 ease-out hover:w-60 focus-within:w-60">
        <nav aria-label="Dashboard" className="flex h-full flex-col gap-1 px-2 py-4">
          <span className="mb-2 h-5 overflow-hidden whitespace-nowrap px-2 text-[10px] font-bold uppercase tracking-widest text-[var(--sd-text-dim)] opacity-0 transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100">
            Workspace
          </span>
          {navLinks.map((link) => {
            const Icon = link.icon;
            const isActive = link.href === "/" ? pathname === "/" : pathname?.startsWith(link.href);

            return (
              <Link
                key={link.href}
                href={link.href}
                aria-label={link.label}
                aria-current={isActive ? "page" : undefined}
                title={link.label}
                className={cn(
                  "flex h-10 min-w-[2.5rem] items-center gap-3 overflow-hidden rounded-lg px-3 text-xs font-medium transition-colors",
                  isActive
                    ? "bg-[var(--sd-pine)] text-[#f7f4ed] font-semibold shadow-xs"
                    : "text-[var(--sd-text-muted)] hover:bg-[var(--sd-panel-hover)] hover:text-[var(--sd-text)]"
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span className="whitespace-nowrap opacity-0 transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100">
                  {link.label}
                </span>
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Approval Modal mounted globally */}
      <ApprovalModal
        isOpen={isApprovalModalOpen}
        onClose={() => setIsApprovalModalOpen(false)}
        token={activeModalToken}
        onDecisionSuccess={() => {
          fetchApprovals();
        }}
      />
    </>
  );
}
