"use client";

import React, { useId, useState } from "react";
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
  const { activeUserId, setActiveUserId } = useChat();
  const titleId = useId();
  const rejectionId = useId();
  const reduceMotion = useReducedMotion();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [isRejecting, setIsRejecting] = useState(false);

  if (!isOpen || !token) return null;

  const isSelfRequester = activeUserId === token.requested_by;

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

          {/* Separation of Duties Rule Banner */}
          {isSelfRequester ? (
            <div className="rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] p-3 text-[13px] text-[var(--sd-danger)] space-y-2">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-[var(--sd-danger)]" />
                <div className="space-y-1">
                  <p className="font-bold">Separation of Duties Policy (ISO 27001 A.9.2)</p>
                  <p className="text-[13px] leading-relaxed text-[var(--sd-danger)]">
                    You cannot sign off on an action you requested (<code className="font-mono font-bold text-[var(--sd-danger)]">{token.requested_by}</code>). A distinct authorized peer must approve this token.
                  </p>
                </div>
              </div>
              <div className="pt-1.5 flex items-center gap-2">
                <span className="text-[11px] text-[var(--sd-danger)]">Switch persona to test peer approval:</span>
                <button
                  type="button"
                  onClick={() => setActiveUserId("dev-admin")}
                  className="px-2 py-0.5 rounded bg-[var(--sd-panel)] text-[var(--sd-pine)] text-[11px] font-bold border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                >
                  Switch to dev-admin
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] p-2.5 text-[13px] text-[var(--sd-success)] flex items-center gap-2">
              <UserCheck className="h-4 w-4 shrink-0" />
              <span>
                Authorized Approver (<code className="font-mono font-bold">{activeUserId}</code>) &mdash; Qualified to sign off.
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
          {isRejecting && (
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
            <button
              onClick={onClose}
              disabled={isSubmitting}
              className="sd-button px-3.5 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[13px] font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
            >
              Cancel
            </button>

            {!isRejecting ? (
              <>
                <button
                  onClick={() => setIsRejecting(true)}
                  disabled={isSubmitting}
                  className="sd-button px-3.5 py-2.5 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] hover:bg-[var(--sd-danger-dim)]/80 text-[13px] font-semibold transition cursor-pointer"
                >
                  Reject Action...
                </button>
                <button
                  onClick={() => handleDecision("approve")}
                  disabled={isSubmitting || isSelfRequester}
                  className="sd-button-primary flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/90 text-[var(--sd-on-accent)] text-[13px] font-bold transition shadow-none cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <span>{isSubmitting ? "Authorizing..." : "Approve & Execute"}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </>
            ) : (
              <button
                onClick={() => handleDecision("reject")}
                disabled={isSubmitting}
                className="sd-button px-4 py-2.5 rounded-xl bg-[var(--sd-danger)] hover:opacity-95 text-[var(--sd-on-accent)] text-[13px] font-bold transition cursor-pointer"
              >
                {isSubmitting ? "Submitting..." : "Confirm Rejection"}
              </button>
            )}
          </div>
        </motion.div>
    </GlassDialog>
  );
}
