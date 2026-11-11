// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { CircleCheck, CircleX, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { CodeBlock, CopyButton, DownloadButton } from "@/components/copy";
import { ModeBadge, PopStatusBadge } from "@/components/pop-status";
import { PageHeader } from "@/components/portal-shell";
import { ErrorState, Loading, QueryView } from "@/components/states";
import { atLeast, useTenant } from "@/components/tenant";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, type Asset, errorMessage, type TunnelTest, unwrap } from "@/lib/api/client";
import { hostOf } from "@/lib/format";

function TunnelScript({ a, tid }: { a: Asset; tid: number }) {
  const [ret, setRet] = useState<"tunnel" | "dsr">("tunnel");
  const [device, setDevice] = useState("");
  const dev = /^[a-zA-Z0-9_.-]{1,15}$/.test(device) ? device : undefined;
  const script = useApi(async () => {
    const r = await api.GET("/api/v1/tenants/{tid}/assets/{aid}/tunnel", {
      params: { path: { tid, aid: a.id }, query: { return: ret, device: dev } },
      parseAs: "text",
    });
    return unwrap(r) as unknown as string;
  }, [tid, a.id, ret, dev]);
  return (
    <div className="grid gap-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="return" label="Replies" hint="Tunnel: replies go back through the PoP (recommended).">
          <Select value={ret} onChange={(e) => setRet(e.target.value as "tunnel" | "dsr")}>
            <option value="tunnel">Back through the tunnel</option>
            <option value="dsr">Directly from your server (DSR)</option>
          </Select>
        </Field>
        <Field id="device" label="Existing tunnel device (optional)" hint="e.g. tunl0; leave empty to create one.">
          <Input value={device} onChange={(e) => setDevice(e.target.value.trim())} placeholder="tunl0" />
        </Field>
      </div>
      <QueryView q={script}>
        {(text) => (
          <>
            <div className="flex flex-wrap gap-2">
              <CopyButton text={text} label="Copy script" />
              <DownloadButton text={text} filename={`sentinel-tunnel-${a.id}.sh`} />
            </div>
            <CodeBlock code={text} label="Tunnel script" />
            <p className="text-sm text-muted-fg">
              Run it as root on your server: <code className="rounded bg-muted px-1 font-mono">sudo sh sentinel-tunnel-{a.id}.sh up</code>{" "}
              (<code className="font-mono">down</code> removes it again).
            </p>
          </>
        )}
      </QueryView>
    </div>
  );
}

function TunnelTester({ a, tid }: { a: Asset; tid: number }) {
  const [res, setRes] = useState<TunnelTest | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    setErr(null);
    try {
      setRes(unwrap(await api.POST("/api/v1/tenants/{tid}/assets/{aid}/tunnel-test", { params: { path: { tid, aid: a.id } } })));
    } catch (e) {
      setErr(errorMessage(e));
      setRes(null);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="grid gap-4">
      <div>
        <Button onClick={run} disabled={busy}>
          {busy ? "Testing…" : "Test the tunnel"}
        </Button>
      </div>
      {busy && <Loading label="Every PoP is sending test packets through the tunnel…" />}
      {err && <Alert tone="danger">{err}</Alert>}
      {res && (
        <div aria-live="polite" className="grid gap-3">
          {res.ok ? (
            <Alert tone="ok" data-testid="tunnel-ok">
              <CircleCheck className="mr-1 inline size-4" aria-hidden /> Tunnel works from every PoP.
            </Alert>
          ) : (
            <Alert tone="danger" data-testid="tunnel-failed">
              <CircleX className="mr-1 inline size-4" aria-hidden />
              {res.pops.length === 0 ? "No PoP is online right now." : "Some PoPs cannot reach your server through the tunnel. Did the script run?"}
            </Alert>
          )}
          {res.pops.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <Th>PoP</Th>
                  <Th>Result</Th>
                  <Th className="text-right">Round trip</Th>
                </tr>
              </thead>
              <tbody>
                {res.pops.map((p) => (
                  <tr key={p.pop}>
                    <Td className="font-mono">{p.pop}</Td>
                    <Td>{p.ok ? `${p.received}/${p.sent} replies` : (p.error ?? "no reply")}</Td>
                    <Td className="text-right tabular-nums">{p.rtt_ms != null ? `${p.rtt_ms} ms` : "–"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </div>
      )}
    </div>
  );
}

function Step({ n, title, description, children }: { n: number; title: string; description?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <span className="mr-2 inline-flex size-6 items-center justify-center rounded-full bg-primary text-xs text-primary-fg" aria-hidden>
            {n}
          </span>
          {title}
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      {children && <CardContent>{children}</CardContent>}
    </Card>
  );
}

export default function AssetPage() {
  const t = useTenant();
  const router = useRouter();
  const { asset } = useParams<{ asset: string }>();
  const aid = Number(asset);
  const q = useApi(async () => unwrap(await api.GET("/api/v1/tenants/{tid}/assets/{aid}", { params: { path: { tid: t.id, aid } } })), [t.id, aid]);
  const status = useApi(
    async () => unwrap(await api.GET("/api/v1/tenants/{tid}/assets/{aid}/status", { params: { path: { tid: t.id, aid } } })),
    [t.id, aid],
    { pollMs: 3000 },
  );
  const [delErr, setDelErr] = useState<string | null>(null);

  if (!Number.isInteger(aid)) return <ErrorState error={new Error("No such protected IP.")} />;

  return (
    <QueryView q={q}>
      {(a) => {
        const ip = hostOf(a.protected_prefix);
        return (
          <>
            <PageHeader
              title={ip}
              description={
                <>
                  Protected IP for your server <span className="font-mono">{a.origin_ip}</span>
                </>
              }
              actions={
                <div className="flex flex-wrap items-center gap-2">
                  <ModeBadge mode={a.policy.mode} />
                  <PopStatusBadge status={status.data} />
                  <CopyButton text={ip} label="Copy IP" />
                </div>
              }
            />
            <div className="grid gap-6">
              {atLeast(t.role, "admin") && (
                <>
                  <Step n={2} title="Set up the tunnel on your server" description="The script adds the protected IP to your server and sets up the IPIP tunnel to our PoPs.">
                    <TunnelScript a={a} tid={t.id} />
                  </Step>
                  <Step n={3} title="Test the tunnel" description="Every PoP pings the protected IP through the tunnel; a reply proves both directions work.">
                    <TunnelTester a={a} tid={t.id} />
                  </Step>
                </>
              )}
              <Step
                n={4}
                title="Point your DNS to the protected IP"
                description={
                  <>
                    Change your domain&apos;s A record to <span className="font-mono">{ip}</span>. Protection starts in observe mode: watch the{" "}
                    <Link className="underline" href={`/t/${t.id}`}>
                      overview
                    </Link>{" "}
                    and switch to mitigate on the{" "}
                    <Link className="underline" href={`/t/${t.id}/rules?asset=${a.id}`}>
                      rules page
                    </Link>{" "}
                    when the traffic looks normal.
                  </>
                }
              />
              {status.data && status.data.pops.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle>Configuration per PoP</CardTitle>
                    <CardDescription>Version {status.data.config_version} of this protected IP&apos;s settings.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <thead>
                        <tr>
                          <Th>PoP</Th>
                          <Th>Applied</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {status.data.pops.map((p) => (
                          <tr key={p.pop}>
                            <Td className="font-mono">{p.pop}</Td>
                            <Td>{p.ok ? "yes" : p.error ? `error: ${p.error}` : "pending"}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </CardContent>
                </Card>
              )}
              {t.role === "owner" && (
                <Card>
                  <CardHeader>
                    <CardTitle>Remove protection</CardTitle>
                    <CardDescription>The protected IP stops working on every PoP and goes back to the pool.</CardDescription>
                  </CardHeader>
                  <CardContent className="grid gap-3">
                    {delErr && <Alert tone="danger">{delErr}</Alert>}
                    <div>
                      <Button
                        variant="danger"
                        onClick={async () => {
                          if (!window.confirm(`Remove ${ip}? Traffic to it will no longer reach your server.`)) return;
                          try {
                            unwrap(await api.DELETE("/api/v1/tenants/{tid}/assets/{aid}", { params: { path: { tid: t.id, aid: a.id } } }));
                            router.push(`/t/${t.id}/assets`);
                          } catch (e) {
                            setDelErr(errorMessage(e));
                          }
                        }}
                      >
                        <Trash2 /> Remove {ip}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </>
        );
      }}
    </QueryView>
  );
}
