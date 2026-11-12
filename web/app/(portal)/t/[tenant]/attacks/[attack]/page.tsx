// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useParams } from "next/navigation";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AttackStatus, Mitigation } from "@/components/attack-badge";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { useTenant } from "@/components/tenant";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, unwrap } from "@/lib/api/client";
import { bps, dateTime, duration, expiresIn, pps, si, vectorName } from "@/lib/format";

const time = (t: number) => new Date(t).toISOString().slice(11, 19);

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-muted-fg">{label}</dt>
      <dd className="mt-1 font-medium tabular-nums">{children}</dd>
    </div>
  );
}

export default function AttackPage() {
  const t = useTenant();
  const { attack } = useParams<{ attack: string }>();
  const aid = Number(attack);
  const q = useApi(
    async () => unwrap(await api.GET("/api/v1/tenants/{tid}/attacks/{aid}", { params: { path: { tid: t.id, aid } } })),
    [t.id, aid],
    { pollMs: 5000 },
  );
  return (
    <QueryView q={q}>
      {(d) => {
        const a = d.attack;
        return (
          <>
            <PageHeader
              title={`${vectorName(a.vector)} on ${a.targets[0] ?? "your protected IPs"}`}
              description={`Started ${dateTime(a.started_at)}`}
              actions={<AttackStatus status={a.status} />}
            />
            <Card>
              <CardContent className="p-5">
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-5">
                  <Fact label="Peak">{pps(a.peak_pps)}</Fact>
                  <Fact label="Peak bandwidth">{bps(a.peak_bps)}</Fact>
                  <Fact label="Duration">{duration(a.started_at, a.ended_at ?? Date.now())}</Fact>
                  <Fact label="Mitigation">
                    <Mitigation ratio={a.dropped_ratio} />
                  </Fact>
                  <Fact label="PoPs">{a.pops.join(", ") || "–"}</Fact>
                </dl>
              </CardContent>
            </Card>
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Traffic during the attack</CardTitle>
                <CardDescription>Packets per second to the tenant, as the workers reported it.</CardDescription>
              </CardHeader>
              <CardContent>
                {d.samples.length < 2 ? (
                  <Empty>Not enough data for a graph yet.</Empty>
                ) : (
                  <figure aria-label="Attack traffic in packets per second" className="h-64 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={d.samples} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                        <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                        <XAxis dataKey="ts" tickFormatter={time} stroke="var(--muted-fg)" fontSize={11} minTickGap={40} />
                        <YAxis tickFormatter={(v: number) => si(v)} stroke="var(--muted-fg)" fontSize={11} width={56} />
                        <Tooltip
                          labelFormatter={(x) => time(Number(x))}
                          formatter={(v) => si(Number(v), "pps")}
                          contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", color: "var(--fg)" }}
                        />
                        <Area isAnimationActive={false} type="monotone" dataKey="pps" name="Inbound" stroke="var(--series-filtered)" fill="var(--series-filtered)" fillOpacity={0.15} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </figure>
                )}
              </CardContent>
            </Card>
            <div className="mt-6 grid gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Top sources</CardTitle>
                </CardHeader>
                <CardContent>
                  {d.top_sources.length === 0 ? (
                    <Empty>No sources sampled.</Empty>
                  ) : (
                    <Table>
                      <thead>
                        <tr>
                          <Th>Source</Th>
                          <Th className="text-right">Peak rate</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.top_sources.map((s) => (
                          <tr key={s.src}>
                            <Td className="font-mono">{s.src}</Td>
                            <Td className="text-right tabular-nums">{pps(s.pps)}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  )}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Blocked sources</CardTitle>
                  <CardDescription>Signed decisions; every block expires on its own.</CardDescription>
                </CardHeader>
                <CardContent>
                  {d.decisions.length === 0 ? (
                    <Empty>No sources blocked.</Empty>
                  ) : (
                    <Table data-testid="blocked-sources">
                      <thead>
                        <tr>
                          <Th>Source</Th>
                          <Th>Expires</Th>
                          <Th>By</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.decisions.map((x) => (
                          <tr key={`${x.issuer}/${x.id}`}>
                            <Td className="font-mono">{x.src}</Td>
                            <Td>{expiresIn(x.expires_at)}</Td>
                            <Td>{x.issuer}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </div>
          </>
        );
      }}
    </QueryView>
  );
}
