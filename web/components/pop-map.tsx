// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { api, unwrap } from "@/lib/api/client";
import { useApi } from "./use-api";

const COLOR: Record<string, string> = { up: "var(--ok)", draining: "var(--warn)", down: "var(--danger)" };

/**
 * The PoPs from the public status, on a stylised anycast diagram: every PoP
 * announces the same prefix; visitors reach the nearest one.
 */
export function PopMap() {
  const q = useApi(async () => unwrap(await api.GET("/api/v1/status")), [], { pollMs: 30_000 });
  const pops = q.data?.pops ?? [];
  const n = Math.max(pops.length, 1);
  const width = 640;
  const x = (i: number) => ((i + 0.5) * width) / n;
  return (
    <figure className="rounded-xl border border-border bg-card p-4">
      <svg viewBox={`0 0 ${width} 220`} className="h-auto w-full" role="img" aria-labelledby="popmap-title popmap-desc">
        <title id="popmap-title">Points of presence</title>
        <desc id="popmap-desc">
          {pops.length === 0
            ? "The list of points of presence is loading or unavailable."
            : pops.map((p) => `${p.id} in ${p.region}: ${p.status}`).join("; ")}
        </desc>
        <text x={width / 2} y="24" textAnchor="middle" fontSize="13" fill="var(--muted-fg)">
          One anycast prefix, announced from every PoP
        </text>
        {pops.map((p, i) => (
          <g key={p.id}>
            <line x1={width / 2} y1="40" x2={x(i)} y2="110" stroke="var(--border)" strokeWidth="2" />
            <circle cx={x(i)} cy="130" r="22" fill="var(--card)" stroke={COLOR[p.status] ?? "var(--muted-fg)"} strokeWidth="4" />
            <text x={x(i)} y="135" textAnchor="middle" fontSize="12" fontWeight="600" fill="var(--fg)">
              {p.id}
            </text>
            <text x={x(i)} y="175" textAnchor="middle" fontSize="12" fill="var(--muted-fg)">
              {p.region}
            </text>
            <text x={x(i)} y="195" textAnchor="middle" fontSize="12" fill={COLOR[p.status] ?? "var(--muted-fg)"}>
              {p.status}
            </text>
          </g>
        ))}
      </svg>
      <figcaption className="mt-2 text-center text-xs text-muted-fg">
        {pops.length > 0 ? `${pops.filter((p) => p.status === "up").length} of ${pops.length} PoPs up` : "Live PoP status"}
      </figcaption>
    </figure>
  );
}
