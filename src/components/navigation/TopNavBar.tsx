"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
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
  }>({ database: false, ollama: false, supabase: false });

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
        });
      })
      .catch(() => {
        setHealthStatus({ database: false, ollama: false, supabase: false });
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
      <header className="border-b border-[var(--sd-border)] bg-[var(--sd-panel)]/95 backdrop-blur-md sticky top-0 z-30 px-5 py-2.5 flex items-center justify-between transition-colors shadow-xs">
        {/* Brand & Platform Identifier */}
        <div className="flex items-center gap-7">
          <Link href="/" className="flex items-center gap-3 group cursor-pointer">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-white overflow-hidden shadow-xs group-hover:scale-105 transition-all duration-200 border border-[var(--sd-border)] p-1">
              <img src="/logo.png" alt="ShieldDesk" className="h-full w-full object-contain" />
            </div>
            <div>
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

          {/* Navigation Links */}
          <nav className="hidden lg:flex items-center gap-1">
            {navLinks.map((link) => {
              const Icon = link.icon;
              const isActive =
                link.href === "/"
                  ? pathname === "/"
                  : pathname?.startsWith(link.href);

              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 cursor-pointer",
                    isActive
                      ? "bg-[var(--sd-pine)] text-[#f7f4ed] font-semibold shadow-xs"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)]"
                  )}
                >
                  <Icon className={cn("h-3.5 w-3.5", isActive ? "text-[#f7f4ed]" : "text-[var(--sd-text-muted)]")} />
                  <span>{link.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right Section: Approvals + Micro Status + Persona Switcher + Sign In */}
        <div className="flex items-center gap-2.5">
          {/* Pending Governance Approvals Pill */}
          {pendingTokens.length > 0 && (
            <button
              onClick={() => {
                setActiveModalToken(pendingTokens[0]);
                setIsApprovalModalOpen(true);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] text-xs font-semibold hover:bg-[var(--sd-warning-dim)]/80 transition-all cursor-pointer shadow-xs animate-pulse"
              title="Click to review pending action requiring human sign-off"
            >
              <Lock className="h-3.5 w-3.5 text-[var(--sd-warning)]" />
              <span>{pendingTokens.length} Pending Approval</span>
            </button>
          )}

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
                    "px-2.5 py-1 rounded-md text-xs font-medium transition-all duration-150 cursor-pointer flex items-center gap-1.5",
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
                  <span>{u.label}</span>
                </button>
              );
            })}
          </div>

          {/* Public Auth / Login link */}
          <Link
            href="/login"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
            title="Sign In / Operator Identity"
          >
            <LogIn className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
            <span className="hidden sm:inline">Sign In</span>
          </Link>
        </div>
      </header>

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
