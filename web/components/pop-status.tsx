// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import type { AssetStatus } from "@/lib/api/client";
import { Badge } from "./ui/badge";

/** "Active on X of Y PoPs" (spec 9.1). */
export function PopStatusBadge({ status }: { status: AssetStatus | undefined }) {
  if (!status) return <Badge>Checking PoPs…</Badge>;
  const { pops_applied: a, pops_total: t } = status;
  if (t === 0) return <Badge tone="warn">No PoP online</Badge>;
  const tone = a === t ? "ok" : a === 0 ? "danger" : "warn";
  return (
    <Badge tone={tone} data-testid="pop-status">
      Active on {a} of {t} PoP{t === 1 ? "" : "s"}
    </Badge>
  );
}

export function ModeBadge({ mode }: { mode: string }) {
  return mode === "mitigate" ? <Badge tone="info">Mitigate</Badge> : <Badge>Observe</Badge>;
}
