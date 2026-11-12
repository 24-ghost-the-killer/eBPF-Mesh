// SPDX-License-Identifier: MIT OR Apache-2.0
import * as React from "react";
import { cn } from "@/lib/utils";

export function Alert({
  tone = "info",
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { tone?: "info" | "danger" | "ok" | "warn" }) {
  const tones = {
    info: "border-primary/40 bg-primary/5",
    danger: "border-danger/40 bg-danger/5 text-danger",
    ok: "border-ok/40 bg-ok/5 text-ok",
    warn: "border-warn/40 bg-warn/5",
  };
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={cn("rounded-md border px-4 py-3 text-sm", tones[tone], className)}
      {...props}
    />
  );
}
