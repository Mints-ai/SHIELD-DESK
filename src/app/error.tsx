"use client";

import React, { useEffect, useState } from "react";
import { ShieldAlert, RefreshCw, Terminal, Home } from "lucide-react";
import Link from "next/link";
import { trackError } from "@/lib/observability/errorTracker";

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const [errorId, setErrorId] = useState<string>("");

  useEffect(() => {
    // Log exception to monitoring
    const id = trackError(error, {
      component: "Next.js App Router Error Boundary",
      extra: { digest: error.digest },
    });
    setErrorId(id);
  }, [error]);

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col items-center justify-center p-4 font-sans relative">
      <div className="max-w-md w-full p-6 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xl space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <h2 className="text-base font-medium text-[var(--sd-text)]">
              Operational Exception Intercepted
            </h2>
            <p className="text-[13px] text-[var(--sd-text-muted)]">
              ShieldDesk isolated this runtime failure to protect state integrity.
            </p>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] font-mono text-[13px] space-y-1">
          <div className="flex justify-between text-[var(--sd-text-dim)] border-b border-[var(--sd-border)] pb-1">
            <span>Incident ID:</span>
            <span className="text-[var(--sd-wheat)]">{errorId || "generating..."}</span>
          </div>
          <div className="pt-1 text-[var(--sd-danger)] break-words">
            {error.message || "An unexpected operational fault occurred."}
          </div>
          {error.digest && (
            <div className="text-[11px] text-[var(--sd-text-dim)]">
              Digest: {error.digest}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 pt-2">
          <button
            onClick={() => reset()}
            className="sd-button sd-button-primary flex-1 px-4 py-2 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium transition cursor-pointer flex items-center justify-center gap-1.5 shadow-xs"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Attempt Recovery</span>
          </button>

          <Link
            href="/"
            className="px-4 py-2 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text)] text-[13px] font-medium transition cursor-pointer flex items-center gap-1.5"
          >
            <Home className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
            <span>SOC Home</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
