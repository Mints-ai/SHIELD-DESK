"use client";

import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/**
 * Minimal Avatar/AvatarFallback pair, API-compatible with shadcn/ui's
 * components/ui/avatar so `import { Avatar, AvatarFallback } from
 * "@/components/ui/avatar"` works without pulling in Radix. If this
 * project later adds the real shadcn avatar (with image support via
 * Radix), this file can be replaced outright — nothing else needs to
 * change.
 */
export function Avatar({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "relative flex shrink-0 overflow-hidden rounded-full",
        className
      )}
      {...props}
    />
  );
}

export function AvatarFallback({
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "flex h-full w-full items-center justify-center rounded-full",
        className
      )}
      {...props}
    />
  );
}

export default Avatar;
