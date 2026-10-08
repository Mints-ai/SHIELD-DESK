"use client";

import React, { useId, useState, useEffect } from "react";
import {
  CheckCircle,
  AlertTriangle,
  Clock,
  UserCheck,
  Lock,
  X,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { GlassDialog } from "@/components/ui/GlassDialog";
import { useChat } from "@/lib/context/ChatContext";
import { AutonomyTierBadge } from "./AutonomyTierBadge";
import { ModelConfidenceMeter } from "./ModelConfidenceMeter";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

interface ApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
  token: ApprovalTokenRecord | null;
  totalCount?: number;
  currentIndex?: number;
  onNavigate?: (index: number) => void;
  onDecisionSuccess?: (updatedToken: ApprovalTokenRecord) => void;
}

export function ApprovalModal({
  isOpen,
  onClose,
  token,
  totalCount = 1,
  currentIndex = 0,
  onNavigate,
  onDecisionSuccess,
}: ApprovalModalProps) {
  const { activeUserId, setActiveUserId, activeUser } = useChat();
  const titleId = useId();
  const rejectionId = useId();
  const reduceMotion = useReducedMotion();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [isRejecting, setIsRejecting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setIsSubmitting(false);
      setErrorMsg(null);
      setSuccessMsg(null);
      setRejectionReason("");
      setIsRejecting(false);
    }
  }, [isOpen, token?.id]);

  if (!isOpen || !token) return null;

  const isElevatedAdmin = activeUser.role === "system_admin" || activeUser.role === "super_admin";
  const isResponder = activeUser.role === "responder";
  const canApproveAny = isElevatedAdmin || isResponder;
  const allowsSelfApproval = isElevatedAdmin && (token.tier === "Tier 1" || token.tier === "Tier 2");
  const isBlockedBySelfRequest = activeUserId === token.requested_by && !allowsSelfApproval;
  const isAnalystRole = activeUser.role === "analyst";
  // Responders cannot approve Tier 3 (break-glass requires admin)
  const canApproveAction =
    canApproveAny &&
    !isBlockedBySelfRequest &&
    (isElevatedAdmin || (isResponder && token.tier !== "Tier 3"));

  const isAlreadyFinalized = token.status !== "pending";

  const handleDecision = async (action: "approve" | "reject") => {
    setIsSubmitting(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`/api/approvals/${encodeURIComponent(token.id)}/decision`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action,
          reason: action === "reject" ? rejectionReason || "Rejected by analyst" : undefined,
        }),
      });

      const body = await res.json();
      if (!res.ok) {
        throw new Error(body?.message || body?.error || `Action failed (${res.status})`);
      }

      setSuccessMsg(body?.message || `Successfully ${action}d action token.`);
      if (onDecisionSuccess && body.token) {
        onDecisionSuccess(body.token);
      }
      if (typeof window !== "undefined") {
        window.dispatchEvent(
          new CustomEvent("shielddesk:approvals-changed", {
            detail: { action, token: body.token },
          })
        );
      }
      setTimeout(() => {
        onClose();
      }, 1500);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Something went wrong.";
      setErrorMsg(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <GlassDialog open={isOpen} onClose={onClose} labelledBy={titleId}>
        <motion.div
          initial={{ opacity: 0, y: reduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: reduceMotion ? 0 : 8 }}
          transition={{ duration: reduceMotion ? 0 : 0.2, ease: "easeOut" }}
          style={{ background: "var(--sd-glass-fill)" }}
          className="relative w-full space-y-5 p-5 text-[var(--sd-text)] sm:p-6"
        >
          {/* Navigation row (only shown when more than 1 approval) */}
          {totalCount > 1 && onNavigate && (
            <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
              <span className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                Approval{" "}
                <span className="font-bold text-[var(--sd-text)]">{currentIndex + 1}</span>
                {" "}of{" "}
                <span className="font-bold text-[var(--sd-text)]">{totalCount}</span>
              </span>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => onNavigate(currentIndex - 1)}
                  disabled={currentIndex === 0}
                  className="flex h-6 w-6 items-center justify-center rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] disabled:opacity-30 disabled:cursor-not-allowed transition cursor-pointer"
                  title="Previous approval"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate(currentIndex + 1)}
                  disabled={currentIndex === totalCount - 1}
                  className="flex h-6 w-6 items-center justify-center rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] disabled:opacity-30 disabled:cursor-not-allowed transition cursor-pointer"
                  title="Next approval"
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* Header */}
          <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--sd-warning-dim)] border border-[var(--sd-warning-border)] text-[var(--sd-warning)] shadow-none">
                <Lock className="h-4 w-4" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 id={titleId} className="text-base font-semibold tracking-tight text-[var(--sd-text)]">Action authorization</h3>
                  <AutonomyTierBadge tier={token.tier} size="sm" showLabel={false} />
                </div>
                <p className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                  Token: {token.id.slice(0, 18)}...
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              type="button"
              aria-label="Close authorization dialog"
              className="sd-button text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] p-1 rounded-lg hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Details Card */}
          <div className="rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] p-4 space-y-4 text-[13px]">
            <div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                Proposed Action
              </span>
              <p className="font-semibold text-sm text-[var(--sd-text)] mt-0.5">
                {token.task_title || token.action_type}
              </p>
              {token.task_description && (
                <p className="text-[13px] text-[var(--sd-text-muted)] mt-1 leading-relaxed">
                  {token.task_description}
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2 border-t border-[var(--sd-border-subtle)]">
              <div>
                <span className="text-[11px] font-medium text-[var(--sd-text-dim)] uppercase tracking-wider">
                  Target Blast Radius
                </span>
                <p className="font-mono text-[11px] text-[var(--sd-text)] mt-0.5">
                  {token.blast_radius}
                </p>
              </div>
              <div>
                <span className="text-[11px] font-medium text-[var(--sd-text-dim)] uppercase tracking-wider">
                  Expires In
                </span>
                <div className="flex items-center gap-1 font-mono text-[11px] text-[var(--sd-warning)] mt-0.5">
                  <Clock className="h-3 w-3" />
                  <span>24 Hours (TTL)</span>
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-[var(--sd-border-subtle)] flex items-center justify-between">
              <div>
                <span className="text-[11px] font-medium text-[var(--sd-text-dim)] uppercase tracking-wider">
                  Requested By
                </span>
                <p className="font-mono text-[11px] text-[var(--sd-text)] mt-0.5">
                  {token.requested_by}
                </p>
              </div>
              <ModelConfidenceMeter confidence={token.model_confidence} />
            </div>
          </div>

          {/* Governance & Role Authorization Banner */}
          {isAnalystRole ? (
            <div className="rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] p-3 text-[13px] text-[var(--sd-danger)] space-y-2">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-[var(--sd-danger)]" />
                <div className="space-y-1">
                  <p className="font-bold">Approval Restricted &mdash; Analyst Role</p>
                  <p className="text-[13px] leading-relaxed text-[var(--sd-danger)]">
                    Analysts cannot approve remediation actions. Only System Admins, Super Admins, or Responders (Tier 1 &amp; 2) are permitted to authorize containment tasks.
                  </p>
                </div>
              </div>
              <div className="pt-1.5 flex items-center gap-2">
                <span className="text-[11px] text-[var(--sd-danger)]">Switch persona to test approval:</span>
                <button
                  type="button"
                  onClick={() => setActiveUserId("dev-admin")}
                  className="px-2 py-0.5 rounded bg-[var(--sd-panel)] text-[var(--sd-pine)] text-[11px] font-bold border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                >
                  Switch to System Admin
                </button>
                <button
                  type="button"
                  onClick={() => setActiveUserId("dev-responder")}
                  className="px-2 py-0.5 rounded bg-[var(--sd-panel)] text-[var(--sd-pine)] text-[11px] font-bold border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                >
                  Switch to Responder
                </button>
              </div>
            </div>

          ) : isBlockedBySelfRequest ? (
            <div className="rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] p-3 text-[13px] text-[var(--sd-danger)] space-y-2">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-[var(--sd-danger)]" />
                <div className="space-y-1">
                  <p className="font-bold">Separation of Duties Policy (Tier 3 Critical)</p>
                  <p className="text-[13px] leading-relaxed text-[var(--sd-danger)]">
                    Tier 3 break-glass actions require sign-off by a distinct administrator. You cannot approve an action you requested (<code className="font-mono font-bold text-[var(--sd-danger)]">{token.requested_by}</code>).
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] p-2.5 text-[13px] text-[var(--sd-success)] flex items-center gap-2">
              <UserCheck className="h-4 w-4 shrink-0" />
              <span>
                {allowsSelfApproval && activeUserId === token.requested_by ? (
                  <>
                    Authorized Approver (<code className="font-mono font-bold">{activeUserId}</code>) &mdash; {activeUser.role === "system_admin" ? "System Admin" : "Super Admin"} self-approval permitted for {token.tier}.
                  </>
                ) : isResponder ? (
                  <>
                    Authorized Approver (<code className="font-mono font-bold">{activeUserId}</code>) &mdash; Responder qualified to sign off on {token.tier} action{token.tier === "Tier 3" ? " (Tier 3 requires admin — use a higher role)" : ""}.
                  </>
                ) : (
                  <>
                    Authorized Approver (<code className="font-mono font-bold">{activeUserId}</code>) &mdash; Qualified to sign off on {token.tier} action.
                  </>
                )}
              </span>
            </div>

          )}

          {/* Finalized Token Notice */}
          {isAlreadyFinalized && (
            <div className="rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] p-3 text-[13px] text-[var(--sd-text-muted)] flex items-center gap-2">
              <Clock className="h-4 w-4 shrink-0 text-[var(--sd-warning)]" />
              <span>
                Token status is <strong className="uppercase font-mono text-[var(--sd-text)]">{token.status}</strong>. This authorization has already concluded.
              </span>
            </div>
          )}

          {/* Feedback Messages */}
          {errorMsg && (
            <div role="alert" className="rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] p-3 text-[13px] text-[var(--sd-danger)]">
              {errorMsg}
            </div>
          )}
          {successMsg && (
            <div role="status" className="rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] p-3 text-[13px] text-[var(--sd-success)] flex items-center gap-2">
              <CheckCircle className="h-4 w-4" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Rejection input area if toggled */}
          {!isAlreadyFinalized && isRejecting && (
            <div className="space-y-1.5">
              <label htmlFor={rejectionId} className="text-[11px] font-semibold text-[var(--sd-text)]">
                Reason for rejection (logged to immutable audit trail):
              </label>
              <textarea
                id={rejectionId}
                autoFocus
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="e.g. Host is a critical production dependency during peak trading window"
                rows={2}
                className="sd-input w-full rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] p-2.5 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-dim)] focus:outline-none focus:border-[var(--sd-pine)] resize-none"
              />
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center justify-end gap-2.5 pt-4 border-t border-[var(--sd-border)]">
            {isAlreadyFinalized ? (
              <button
                type="button"
                onClick={onClose}
                className="sd-button px-4 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[13px] font-semibold text-[var(--sd-text)] transition cursor-pointer"
              >
                Close
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => {
                    if (isRejecting) {
                      setIsRejecting(false);
                      setErrorMsg(null);
                    } else {
                      onClose();
                    }
                  }}
                  disabled={isSubmitting}
                  className="sd-button px-3.5 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[13px] font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                >
                  {isRejecting ? "Back" : "Cancel"}
                </button>

                {!isRejecting ? (
                  <>
                    <button
                      type="button"
                      onClick={() => setIsRejecting(true)}
                      disabled={isSubmitting}
                      className="px-4 py-2.5 rounded-xl border border-[#8a3025]/50 bg-[#8a3025]/15 text-[#e07567] hover:bg-[#8a3025]/25 text-[13px] font-semibold transition cursor-pointer"
                    >
                      Reject Action...
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDecision("approve")}
                      disabled={isSubmitting || !canApproveAction}
                      className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#c8aa6f] to-[#a07f3a] hover:from-[#d5b97d] hover:to-[#af8d44] text-[#171208] text-[13px] font-bold shadow-[0_4px_16px_rgba(160,127,58,0.25)] transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <span>{isSubmitting ? "Authorizing..." : "Approve & Execute"}</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    onClick={() => handleDecision("reject")}
                    disabled={isSubmitting}
                    className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#8a3025] to-[#6d241c] hover:from-[#9b372b] hover:to-[#7d2a20] text-white border border-[#b84a3c]/40 text-[13px] font-bold shadow-[0_2px_12px_rgba(138,48,37,0.3)] transition cursor-pointer"
                  >
                    {isSubmitting ? "Submitting..." : "Confirm Rejection"}
                  </button>
                )}
              </>
            )}
          </div>
        </motion.div>
    </GlassDialog>
  );
}
