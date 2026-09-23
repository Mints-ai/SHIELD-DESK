"use client";

import React, { useEffect } from "react";
import { trackError } from "@/lib/observability/errorTracker";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    trackError(error, { component: "Global Root Error Boundary" });
  }, [error]);

  return (
    <html lang="en">
      <body className="bg-[#f7f4ed] text-[#1a1f1d] min-h-screen flex items-center justify-center p-4 font-sans">
        <div className="max-w-md w-full p-6 rounded-2xl border border-[#d6cfbe] bg-[#ffffff] shadow-xl text-center space-y-4">
          <div className="h-10 w-10 mx-auto rounded-xl bg-[#dc2626] text-white flex items-center justify-center font-bold">
            !
          </div>
          <h2 className="text-base font-bold text-[#1a1f1d]">Critical System Error</h2>
          <p className="text-xs text-[#526058]">
            A root level rendering fault was caught by ShieldDesk governance layer.
          </p>
          <div className="p-3 rounded-xl bg-[#121417] text-[#f87171] font-mono text-xs text-left">
            {error.message || "Root layout failed to mount."}
          </div>
          <button
            onClick={() => reset()}
            className="w-full py-2 rounded-lg bg-[#123826] hover:bg-[#1a4d35] text-[#f7f4ed] text-xs font-semibold cursor-pointer shadow-xs"
          >
            Reload Application
          </button>
        </div>
      </body>
    </html>
  );
}
