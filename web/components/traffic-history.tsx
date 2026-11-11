// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ApiError, api, unwrap } from "@/lib/api/client";
import { si } from "@/lib/format";
import { Empty, ErrorState, Loading } from "./states";
import { useApi } from "./use-api";

const COLORS = ["var(--series-in)", "var(--series-clean)", "var(--series-filtered)", "var(--warn)", "var(--muted-fg)"];
const hhmm = (t: number) => new Date(t).toISOString().slice(11, 16);

/** Rows {ts, <pop>: in_pps, ...} for the chart. */
export function pivot(pops: { pop: string; points: { ts: number; in_pps: number }[] }[]) {
  const rows = new Map<number, Record<string, number>>();
  for (const p of pops)
    for (const pt of p.points) {
      const r = rows.get(pt.ts) ?? { ts: pt.ts };
      r[p.pop] = pt.in_pps;
      rows.set(pt.ts, r);
    }
  return [...rows.values()].sort((a, b) => a.ts! - b.ts!);
}

/** Last hour per PoP, from ClickHouse (traffic_1m). */
export function TrafficHistory({ tenant }: { tenant: number }) {
  const q = useApi(
    async () => unwrap(await api.GET("/api/v1/tenants/{tid}/traffic", { params: { path: { tid: tenant }, query: { step: 60 } } })),
    [tenant],
    { pollMs: 60_000 },
  );
  if (q.error instanceof ApiError && q.error.status === 503)
    return <Empty>Traffic history is not available on this installation.</Empty>;
  if (q.error && !q.data) return <ErrorState error={q.error} retry={q.reload} />;
  if (!q.data) return <Loading />;
  if (q.data.pops.length === 0) return <Empty>No traffic in the last hour.</Empty>;
  const names = q.data.pops.map((p) => p.pop);
  return (
    <figure aria-label="Inbound packets per second per PoP, last hour" className="h-64 w-full" data-testid="traffic-history">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={pivot(q.data.pops)} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis dataKey="ts" tickFormatter={hhmm} stroke="var(--muted-fg)" fontSize={11} minTickGap={40} />
          <YAxis tickFormatter={(v: number) => si(v)} stroke="var(--muted-fg)" fontSize={11} width={56} />
          <Tooltip
            labelFormatter={(t) => hhmm(Number(t))}
            formatter={(v) => si(Number(v), "pps")}
            contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", color: "var(--fg)" }}
          />
          <Legend />
          {names.map((n, i) => (
            <Line key={n} isAnimationActive={false} type="monotone" dataKey={n} stroke={COLORS[i % COLORS.length]} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </figure>
  );
}
