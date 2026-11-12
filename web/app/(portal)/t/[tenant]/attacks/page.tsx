// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { AttackStatus } from "@/components/attack-badge";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { useTenant } from "@/components/tenant";
import { Card, CardContent } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, unwrap } from "@/lib/api/client";
import { bps, dateTime, duration, pps, vectorName } from "@/lib/format";

export default function AttacksPage() {
  const t = useTenant();
  const q = useApi(
    async () => unwrap(await api.GET("/api/v1/tenants/{tid}/attacks", { params: { path: { tid: t.id } } })),
    [t.id],
    { pollMs: 5000 },
  );
  return (
    <>
      <PageHeader title="Attacks" description="Detected automatically; the largest sources are blocked at the PoPs with a TTL." />
      <Card>
        <CardContent className="p-0 sm:p-2">
          <QueryView q={q}>
            {(list) =>
              list.length === 0 ? (
                <div className="p-4">
                  <Empty>No attacks detected.</Empty>
                </div>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>Started</Th>
                      <Th>Vector</Th>
                      <Th>Status</Th>
                      <Th className="text-right">Peak</Th>
                      <Th className="text-right">Duration</Th>
                      <Th>Target</Th>
                      <Th className="text-right">Blocked</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((a) => (
                      <tr key={a.id}>
                        <Td>
                          <Link className="text-primary underline" href={`/t/${t.id}/attacks/${a.id}`}>
                            {dateTime(a.started_at)}
                          </Link>
                        </Td>
                        <Td>{vectorName(a.vector)}</Td>
                        <Td>
                          <AttackStatus status={a.status} />
                        </Td>
                        <Td className="text-right tabular-nums">
                          {pps(a.peak_pps)}
                          <span className="block text-xs text-muted-fg">{bps(a.peak_bps)}</span>
                        </Td>
                        <Td className="text-right tabular-nums">{duration(a.started_at, a.ended_at ?? Date.now())}</Td>
                        <Td className="font-mono">{a.targets[0] ?? "–"}</Td>
                        <Td className="text-right tabular-nums">{a.decisions}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )
            }
          </QueryView>
        </CardContent>
      </Card>
    </>
  );
}
