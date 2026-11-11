// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { useState } from "react";
import { LiveChart } from "@/components/live-chart";
import { PageHeader } from "@/components/portal-shell";
import { QueryView } from "@/components/states";
import { useTenant } from "@/components/tenant";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { useLive } from "@/components/use-live";
import { api, unwrap } from "@/lib/api/client";
import { bps, pps } from "@/lib/format";

function Stat({ label, value, sub, testid }: { label: string; value: string; sub: string; testid: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs uppercase tracking-wide text-muted-fg">{label}</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums" data-testid={testid}>
          {value}
        </p>
        <p className="text-xs text-muted-fg tabular-nums">{sub}</p>
      </CardContent>
    </Card>
  );
}

export default function Overview() {
  const t = useTenant();
  const live = useLive(t.id);
  const [unit, setUnit] = useState<"pps" | "bps">("pps");
  const assets = useApi(async () => unwrap(await api.GET("/api/v1/tenants/{tid}/assets", { params: { path: { tid: t.id } } })), [t.id]);
  const observe = (assets.data ?? []).every((a) => a.policy.mode !== "mitigate");
  const r = live.last?.total;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Traffic to your protected IPs across all PoPs, updated every second."
        actions={
          <Badge tone={live.status === "open" ? "ok" : "warn"} aria-live="polite">
            {live.status === "open" ? "Live" : live.status === "connecting" ? "Connecting…" : "Reconnecting…"}
          </Badge>
        }
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label="Inbound" testid="rate-in" value={r ? pps(r.in_pps) : "–"} sub={r ? bps(r.in_bps) : ""} />
        <Stat label={observe ? "Clean" : "Delivered"} testid="rate-clean" value={r ? pps(r.clean_pps) : "–"} sub={r ? bps(r.clean_bps) : ""} />
        <Stat
          label={observe ? "Would drop (observe)" : "Dropped"}
          testid="rate-filtered"
          value={r ? pps(r.filtered_pps) : "–"}
          sub={r ? bps(r.filtered_bps) : ""}
        />
      </div>

      <Card className="mt-6">
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle>Live traffic</CardTitle>
            <CardDescription>Last two minutes.</CardDescription>
          </div>
          <div role="group" aria-label="Unit" className="flex gap-1">
            {(["pps", "bps"] as const).map((u) => (
              <Button key={u} size="sm" variant={unit === u ? "default" : "outline"} aria-pressed={unit === u} onClick={() => setUnit(u)}>
                {u === "pps" ? "Packets/s" : "Bits/s"}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          <LiveChart data={unit === "pps" ? live.pps : live.bps} unit={unit} observe={observe} />
        </CardContent>
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Traffic per PoP</CardTitle>
          </CardHeader>
          <CardContent>
            {!live.last || live.last.pops.length === 0 ? (
              <p className="text-sm text-muted-fg">No PoP has reported in the last few seconds.</p>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>PoP</Th>
                    <Th className="text-right">Inbound</Th>
                    <Th className="text-right">{observe ? "Would drop" : "Dropped"}</Th>
                  </tr>
                </thead>
                <tbody>
                  {live.last.pops.map((p) => (
                    <tr key={p.pop}>
                      <Td className="font-mono">{p.pop}</Td>
                      <Td className="text-right tabular-nums">{pps(p.in_pps)}</Td>
                      <Td className="text-right tabular-nums">{pps(p.filtered_pps)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Protected IPs</CardTitle>
          </CardHeader>
          <CardContent>
            <QueryView q={assets}>
              {(list) =>
                list.length === 0 ? (
                  <p className="text-sm text-muted-fg">
                    Nothing protected yet.{" "}
                    <Link className="text-primary underline" href={`/t/${t.id}/assets/new`}>
                      Protect a server
                    </Link>
                  </p>
                ) : (
                  <ul className="grid gap-2 text-sm">
                    {list.map((a) => (
                      <li key={a.id} className="flex items-center justify-between gap-2">
                        <Link className="font-mono text-primary underline" href={`/t/${t.id}/assets/${a.id}`}>
                          {a.protected_prefix.replace(/\/32$/, "")}
                        </Link>
                        <Badge tone={a.policy.mode === "mitigate" ? "info" : "neutral"}>{a.policy.mode}</Badge>
                      </li>
                    ))}
                  </ul>
                )
              }
            </QueryView>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
