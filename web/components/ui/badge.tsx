// SPDX-License-Identifier: MIT OR Apache-2.0
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/utils";

const badge = cva("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium", {
  variants: {
    tone: {
      neutral: "border-border bg-muted text-fg",
      ok: "border-ok/40 bg-ok/10 text-ok",
      warn: "border-warn/40 bg-warn/10 text-warn",
      danger: "border-danger/40 bg-danger/10 text-danger",
      info: "border-primary/40 bg-primary/10 text-primary",
    },
  },
  defaultVariants: { tone: "neutral" },
});

export function Badge({
  className,
  tone,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) {
  return <span className={cn(badge({ tone }), className)} {...props} />;
}
