// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useState } from "react";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, errorMessage, unwrap } from "@/lib/api/client";
import { dateTime, expiresIn } from "@/lib/format";
import { checkRulePrefix } from "@/lib/validate";

export default function DecisionsPage() {
  const q = useApi(async () => unwrap(await api.GET("/api/v1/admin/decisions")), [], { pollMs: 5000 });
  const [src, setSrc] = useState("");
  const [tenant, setTenant] = useState("0");
  const [ttl, setTtl] = useState(3600);
  const [reason, setReason] = useState("manual");
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setOk(null);
    const pe = checkRulePrefix(src);
    if (pe) {
      setErr(pe);
      return;
    }
    try {
      const d = unwrap(
        await api.POST("/api/v1/admin/decisions", {
          body: { src: src.trim(), tenant: Number(tenant) || 0, ttl_s: ttl, reason: reason.trim() },
        }),
      );
      setOk(`Block ${d.src} signed and sent to every PoP (expires ${expiresIn(d.expires_at)}).`);
      setSrc("");
      q.reload();
    } catch (x) {
      setErr(errorMessage(x));
    }
  }

  return (
    <>
      <PageHeader title="Decisions" description="Signed blocks from the analysis workers and from operators. Every block expires." />
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Block a source</CardTitle>
          <CardDescription>Signed with the API&apos;s key; the PoPs verify it like a worker&apos;s decision.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid gap-4 sm:grid-cols-[1fr_8rem_9rem_10rem_auto] sm:items-end" aria-label="Block a source">
            {err && <Alert tone="danger" className="sm:col-span-5">{err}</Alert>}
            {ok && <Alert tone="ok" className="sm:col-span-5">{ok}</Alert>}
            <Field id="dec-src" label="Source address or prefix">
              <Input value={src} onChange={(e) => setSrc(e.target.value)} placeholder="203.0.113.0/24" />
            </Field>
            <Field id="dec-tenant" label="Tenant" hint="0 = all">
              <Input value={tenant} onChange={(e) => setTenant(e.target.value)} inputMode="numeric" />
            </Field>
            <Field id="dec-ttl" label="Expires after">
              <Select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
                <option value={600}>10 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={86400}>24 hours</option>
              </Select>
            </Field>
            <Field id="dec-reason" label="Reason">
              <Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={32} />
            </Field>
            <Button type="submit">Block</Button>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="p-0 sm:p-2">
          <QueryView q={q}>
            {(list) =>
              list.length === 0 ? (
                <div className="p-4">
                  <Empty>No decisions yet.</Empty>
                </div>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>Time</Th>
                      <Th>Source</Th>
                      <Th>Tenant</Th>
                      <Th>Reason</Th>
                      <Th>Issuer</Th>
                      <Th>Expires</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((d) => (
                      <tr key={`${d.issuer}/${d.id}`}>
                        <Td>{dateTime(d.ts)}</Td>
                        <Td className="font-mono">{d.src}</Td>
                        <Td>{d.tenant_id ?? "all"}</Td>
                        <Td>{d.reason}</Td>
                        <Td>{d.issuer}</Td>
                        <Td>{d.active ? <Badge tone="danger">{expiresIn(d.expires_at)}</Badge> : <Badge>expired</Badge>}</Td>
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
