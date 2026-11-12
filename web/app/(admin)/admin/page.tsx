// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useState } from "react";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, errorMessage, unwrap } from "@/lib/api/client";
import { dateTime } from "@/lib/format";

const tone = (s: string) => (s === "up" ? "ok" : s === "draining" ? "warn" : "danger");

export default function PopsPage() {
  const pops = useApi(async () => unwrap(await api.GET("/api/v1/admin/pops")), [], { pollMs: 5000 });
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function drain(id: string, drain: boolean) {
    const verb = drain ? "Drain" : "Undrain";
    if (drain && !window.confirm(`${verb} ${id}? Its traffic moves to other PoPs.`)) return;
    setErr(null);
    try {
      unwrap(await api.POST("/api/v1/admin/pops/{id}/drain", { params: { path: { id } }, body: { drain } }));
      setMsg(`${verb}ing ${id}: the PoP updates its BGP announcement within seconds.`);
      pops.reload();
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  async function killswitch(observe: boolean) {
    const what = observe ? "turn ON the kill switch (every PoP stops dropping)" : "turn the kill switch off";
    if (!window.confirm(`Really ${what}?`)) return;
    setErr(null);
    try {
      unwrap(await api.POST("/api/v1/admin/killswitch", { body: { observe } }));
      setMsg(observe ? "Kill switch on: all PoPs only observe." : "Kill switch off: PoPs enforce policies again.");
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  return (
    <>
      <PageHeader title="PoPs" description="Health from the agents, every few seconds. Draining prepends the AS path so traffic gradually prefers other PoPs." />
      {err && <Alert tone="danger" className="mb-4">{err}</Alert>}
      {msg && <Alert tone="ok" className="mb-4">{msg}</Alert>}
      <Card>
        <CardContent className="p-0 sm:p-2">
          <QueryView q={pops}>
            {(list) =>
              list.length === 0 ? (
                <div className="p-4">
                  <Empty>No PoP has reported yet.</Empty>
                </div>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>PoP</Th>
                      <Th>Region</Th>
                      <Th>Address</Th>
                      <Th>Status</Th>
                      <Th>Last seen</Th>
                      <Th className="text-right">Config</Th>
                      <Th>
                        <span className="sr-only">Actions</span>
                      </Th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((p) => (
                      <tr key={p.id} data-testid={`pop-${p.id}`}>
                        <Td className="font-mono">{p.id}</Td>
                        <Td>{p.region}</Td>
                        <Td className="font-mono">{p.unicast_ip ?? "–"}</Td>
                        <Td>
                          <Badge tone={tone(p.status)}>{p.status}</Badge>
                        </Td>
                        <Td>{dateTime(p.last_seen)}</Td>
                        <Td className="text-right tabular-nums">{p.config_version_applied ?? "–"}</Td>
                        <Td className="text-right">
                          {p.status === "draining" ? (
                            <Button size="sm" variant="outline" onClick={() => drain(p.id, false)}>
                              Undrain {p.id}
                            </Button>
                          ) : (
                            <Button size="sm" variant="outline" onClick={() => drain(p.id, true)}>
                              Drain {p.id}
                            </Button>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )
            }
          </QueryView>
        </CardContent>
      </Card>
      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Kill switch</CardTitle>
          <CardDescription>Puts every PoP into observe mode: counts verdicts, drops nothing. For emergencies.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Button variant="danger" onClick={() => killswitch(true)}>
            Kill switch on
          </Button>
          <Button variant="outline" onClick={() => killswitch(false)}>
            Kill switch off
          </Button>
        </CardContent>
      </Card>
    </>
  );
}
