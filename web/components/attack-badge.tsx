// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Badge } from "./ui/badge";

export function AttackStatus({ status }: { status: string }) {
  return status === "active" ? (
    <Badge tone="danger" data-testid="attack-active">
      Under attack
    </Badge>
  ) : (
    <Badge tone="neutral">Ended</Badge>
  );
}

/** "62% dropped at the PoPs". */
export function Mitigation({ ratio }: { ratio: number }) {
  const pct = Math.round(ratio * 100);
  return <span className="tabular-nums">{pct}% dropped</span>;
}
