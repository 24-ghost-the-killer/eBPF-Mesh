// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { si } from "@/lib/format";
import type { Point } from "@/lib/live";

const time = (t: number) => new Date(t).toISOString().slice(11, 19);

/** In / clean / filtered over the last two minutes. */
export function LiveChart({ data, unit, observe }: { data: Point[]; unit: "pps" | "bps"; observe: boolean }) {
  return (
    <figure aria-label={`Live traffic in ${unit}`} className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis dataKey="t" tickFormatter={time} stroke="var(--muted-fg)" fontSize={11} minTickGap={40} />
          <YAxis tickFormatter={(v: number) => si(v)} stroke="var(--muted-fg)" fontSize={11} width={56} />
          <Tooltip
            labelFormatter={(t) => time(Number(t))}
            formatter={(v) => si(Number(v), unit)}
            contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", color: "var(--fg)" }}
          />
          <Legend />
          <Area isAnimationActive={false} type="monotone" dataKey="in" name="Inbound" stroke="var(--series-in)" fill="var(--series-in)" fillOpacity={0.08} />
          <Area isAnimationActive={false} type="monotone" dataKey="clean" name={observe ? "Clean" : "Delivered"} stroke="var(--series-clean)" fill="var(--series-clean)" fillOpacity={0.15} />
          <Area isAnimationActive={false} type="monotone" dataKey="filtered" name={observe ? "Would drop (observe)" : "Dropped"} stroke="var(--series-filtered)" fill="var(--series-filtered)" fillOpacity={0.15} />
        </AreaChart>
      </ResponsiveContainer>
    </figure>
  );
}
