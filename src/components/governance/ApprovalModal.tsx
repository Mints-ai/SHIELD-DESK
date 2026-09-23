"use client";

import React, { useState } from "react";
import {
  CheckCircle,
  AlertTriangle,
  Clock,
  UserCheck,
  Lock,
  X,
  ArrowRight,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useChat } from "@/lib/context/ChatContext";
import { AutonomyTierBadge } from "./AutonomyTierBadge";
import { ModelConfidenceMeter } from "./ModelConfidenceMeter";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

interface ApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
  token: ApprovalTokenRecord | null;
  onDecisionSuccess?: (updatedToken: ApprovalTokenRecord) => void;
}

export function ApprovalModal({
  isOpen,
  onClose,
  token,
  onDecisionSuccess,
}: ApprovalModalProps) {
  const { activeUserId, setActiveUserId } = useChat();
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
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0d2419]/40 backdrop-blur-sm">
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 8 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
          className="relative w-full max-w-lg rounded-2xl border border-[var(--sd-border-strong)] bg-[var(--sd-panel)] p-6 shadow-2xl space-y-5 text-[var(--sd-text)]"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--sd-warning-dim)] border border-[var(--sd-warning-border)] text-[var(--sd-warning)] shadow-xs">
                <Lock className="h-4 w-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-[var(--sd-text)]">Action Authorization Request</h3>
                  <AutonomyTierBadge tier={token.tier} size="sm" showLabel={false} />
                </div>
                <p className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                  Token: {token.id.slice(0, 18)}...
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] p-1 rounded-lg hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Details Card */}
          <div className="rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] p-4 space-y-3 text-xs">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                Proposed Action
              </span>
              <p className="font-semibold text-sm text-[var(--sd-text)] mt-0.5">
                {token.task_title || token.action_type}
              </p>
              {token.task_description && (
                <p className="text-[11.5px] text-[var(--sd-text-muted)] mt-1 leading-relaxed">
                  {token.task_description}
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2 border-t border-[var(--sd-border-subtle)]">
              <div>
                <span className="text-[10px] font-medium text-[var(--sd-text-dim)] uppercase tracking-wider">
                  Target Blast Radius
                </span>
                <p className="font-mono text-[11px] text-[var(--sd-text)] mt-0.5">
                  {token.blast_radius}
                </p>
              </div>
              <div>
                <span className="text-[10px] font-medium text-[var(--sd-text-dim)] uppercase tracking-wider">
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
                <span className="text-[10px] font-medium text-[var(--sd-text-dim)] uppercase tracking-wider">
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
            <div className="rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] p-3 text-xs text-[var(--sd-danger)] space-y-2">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-[var(--sd-danger)]" />
                <div className="space-y-1">
                  <p className="font-bold">Separation of Duties Policy (ISO 27001 A.9.2)</p>
                  <p className="text-[11px] leading-relaxed text-[var(--sd-danger)]">
                    You cannot sign off on an action you requested (<code className="font-mono font-bold text-[var(--sd-danger)]">{token.requested_by}</code>). A distinct authorized peer must approve this token.
                  </p>
                </div>
              </div>
              <div className="pt-1.5 flex items-center gap-2">
                <span className="text-[11px] text-[var(--sd-danger)]">Switch persona to test peer approval:</span>
                <button
                  type="button"
                  onClick={() => setActiveUserId("dev-admin")}
                  className="px-2 py-0.5 rounded bg-[var(--sd-panel)] text-[var(--sd-pine)] text-[10px] font-bold border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                >
                  Switch to dev-admin
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] p-2.5 text-xs text-[var(--sd-success)] flex items-center gap-2">
              <UserCheck className="h-4 w-4 shrink-0" />
              <span>
                Authorized Approver (<code className="font-mono font-bold">{activeUserId}</code>) &mdash; Qualified to sign off.
              </span>
            </div>
          )}

          {/* Feedback Messages */}
          {errorMsg && (
            <div className="rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] p-3 text-xs text-[var(--sd-danger)]">
              {errorMsg}
            </div>
          )}
          {successMsg && (
            <div className="rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] p-3 text-xs text-[var(--sd-success)] flex items-center gap-2">
              <CheckCircle className="h-4 w-4" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Rejection input area if toggled */}
          {isRejecting && (
            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-[var(--sd-text)]">
                Reason for rejection (logged to immutable audit trail):
              </label>
              <textarea
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="e.g. Host is a critical production dependency during peak trading window"
                rows={2}
                className="w-full rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] p-2.5 text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-dim)] focus:outline-none focus:border-[var(--sd-pine)] resize-none"
              />
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-[var(--sd-border)]">
            <button
              onClick={onClose}
              disabled={isSubmitting}
              className="px-3.5 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
            >
              Cancel
            </button>

            {!isRejecting ? (
              <>
                <button
                  onClick={() => setIsRejecting(true)}
                  disabled={isSubmitting}
                  className="px-3.5 py-2 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] hover:bg-[var(--sd-danger-dim)]/80 text-xs font-semibold transition cursor-pointer"
                >
                  Reject Action...
                </button>
                <button
                  onClick={() => handleDecision("approve")}
                  disabled={isSubmitting || isSelfRequester}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/90 text-[#f7f4ed] text-xs font-bold transition shadow-md cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <span>{isSubmitting ? "Authorizing..." : "Approve & Execute"}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </>
            ) : (
              <button
                onClick={() => handleDecision("reject")}
                disabled={isSubmitting}
                className="px-4 py-2 rounded-xl bg-[var(--sd-danger)] hover:opacity-95 text-white text-xs font-bold transition cursor-pointer"
              >
                {isSubmitting ? "Submitting..." : "Confirm Rejection"}
              </button>
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
