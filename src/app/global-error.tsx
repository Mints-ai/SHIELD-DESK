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
      <body style={{ backgroundImage: "radial-gradient(ellipse at 15% 15%,rgba(11,107,80,.35),transparent 55%),linear-gradient(125deg,#07100D,#0A1713)" }} className="bg-[#07100D] text-[#F2EFE9] min-h-screen flex items-center justify-center p-4 font-sans">
        <div style={{ background: "linear-gradient(145deg,rgba(16,31,26,.85),rgba(7,16,13,.92))", boxShadow: "inset 0 1px 0 rgba(242,239,233,.20),0 20px 50px rgba(0,0,0,.45)" }} className="max-w-md w-full p-6 rounded-2xl border border-[#D8C49A]/30 text-center space-y-4">
          <div className="h-10 w-10 mx-auto rounded-xl bg-[#dfa398] text-[#07100D] flex items-center justify-center font-medium font-mono">
            !
          </div>
          <h2 className="text-base font-semibold text-[#F2EFE9] font-orbitron">Critical System Error</h2>
          <p className="text-[13px] text-[#9EB2A7]">
            A root level rendering fault was caught by ShieldDesk governance layer.
          </p>
          <div className="p-3 rounded-xl bg-[#050B09] text-[#dfa398] font-mono text-[13px] text-left border border-[#D8C49A]/15">
            {error.message || "Root layout failed to mount."}
          </div>
          <button
            onClick={() => reset()}
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-[#0E8563] to-[#0B6B50] hover:from-[#119E76] hover:to-[#0D7558] text-[#FFFFFF] border border-[#D8C49A]/30 text-[13px] font-semibold cursor-pointer shadow-md transition"
          >
            Reload Application
          </button>
        </div>
      </body>
    </html>
  );
}
