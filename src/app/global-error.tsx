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
      <body style={{ backgroundImage: "radial-gradient(ellipse at 15% 15%,rgba(160,127,58,.30),transparent 55%),linear-gradient(125deg,#000,#0b0d0f)" }} className="bg-[#000000] text-[#e3d5bb] min-h-screen flex items-center justify-center p-4 font-sans">
        <div style={{ background: "linear-gradient(145deg,rgba(83,89,95,.56),rgba(31,34,38,.78))", boxShadow: "inset 0 1px 0 rgba(255,248,231,.25),0 20px 50px rgba(0,0,0,.28)" }} className="max-w-md w-full p-6 rounded-2xl border border-[#c8aa6f70] text-center space-y-4">
          <div className="h-10 w-10 mx-auto rounded-xl bg-[#d99a8e] text-[#171208] flex items-center justify-center font-medium">
            !
          </div>
          <h2 className="text-base font-medium text-[#e3d5bb]">Critical System Error</h2>
          <p className="text-[13px] text-[#aba69b]">
            A root level rendering fault was caught by ShieldDesk governance layer.
          </p>
          <div className="p-3 rounded-xl bg-[#10100e] text-[#d99a8e] font-mono text-[13px] text-left">
            {error.message || "Root layout failed to mount."}
          </div>
          <button
            onClick={() => reset()}
            className="w-full py-2 rounded-lg bg-[#a07f3a] hover:bg-[#c8aa6f] text-[#171208] text-[13px] font-medium cursor-pointer shadow-xs"
          >
            Reload Application
          </button>
        </div>
      </body>
    </html>
  );
}
