// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useState } from "react";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, errorMessage, unwrap } from "@/lib/api/client";
import { dateTime } from "@/lib/format";

export default function KeysPage() {
  const q = useApi(async () => unwrap(await api.GET("/api/v1/admin/signing-keys")), []);
  const [issuer, setIssuer] = useState("");
  const [key, setKey] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      unwrap(await api.POST("/api/v1/admin/signing-keys", { body: { issuer: issuer.trim(), public_key: key.trim() } }));
      setIssuer("");
      setKey("");
      q.reload();
    } catch (x) {
      setErr(errorMessage(x));
    }
  }

  return (
    <>
      <PageHeader title="Signing keys" description="Issuers whose decisions the PoPs accept. Revoking one takes effect on every PoP within seconds." />
      {err && <Alert tone="danger" className="mb-4">{err}</Alert>}
      <Card className="mb-6">
        <CardContent className="p-0 sm:p-2">
          <QueryView q={q}>
            {(list) =>
              list.length === 0 ? (
                <div className="p-4">
                  <Empty>No trusted issuers.</Empty>
                </div>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>Issuer</Th>
                      <Th>Public key</Th>
                      <Th>Added</Th>
                      <Th>Status</Th>
                      <Th>
                        <span className="sr-only">Actions</span>
                      </Th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((k) => (
                      <tr key={k.issuer}>
                        <Td className="font-mono">{k.issuer}</Td>
                        <Td className="max-w-56 truncate font-mono text-xs" title={k.public_key}>
                          {k.public_key}
                        </Td>
                        <Td>{dateTime(k.created_at)}</Td>
                        <Td>{k.revoked ? <Badge tone="danger">revoked</Badge> : <Badge tone="ok">trusted</Badge>}</Td>
                        <Td className="text-right">
                          {!k.revoked && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={async () => {
                                if (!window.confirm(`Revoke ${k.issuer}? Its decisions will be refused everywhere.`)) return;
                                try {
                                  unwrap(await api.POST("/api/v1/admin/signing-keys/{issuer}/revoke", { params: { path: { issuer: k.issuer } } }));
                                  q.reload();
                                } catch (x) {
                                  setErr(errorMessage(x));
                                }
                              }}
                            >
                              Revoke {k.issuer}
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
      <Card>
        <CardHeader>
          <CardTitle>Trust a worker</CardTitle>
          <CardDescription>
            The public key printed by <code className="font-mono">sentinel-worker key generate</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={add} className="grid gap-4 sm:grid-cols-[12rem_1fr_auto] sm:items-end" aria-label="Trust a worker">
            <Field id="key-issuer" label="Issuer">
              <Input value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="worker-3" />
            </Field>
            <Field id="key-pub" label="Public key (base64)">
              <Input value={key} onChange={(e) => setKey(e.target.value)} />
            </Field>
            <Button type="submit">Trust</Button>
          </form>
        </CardContent>
      </Card>
    </>
  );
}
