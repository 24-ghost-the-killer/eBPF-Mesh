// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Trash2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { PolicyEditor } from "@/components/policy-editor";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { atLeast, useTenant } from "@/components/tenant";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, errorMessage, type Rule, unwrap } from "@/lib/api/client";
import { expiresIn, hostOf } from "@/lib/format";
import { checkRulePrefix } from "@/lib/validate";

const TTLS = [
  ["1 hour", 3600],
  ["24 hours", 86400],
  ["7 days", 7 * 86400],
  ["30 days", 30 * 86400],
] as const;

function RuleForm({ onAdded }: { onAdded: () => void }) {
  const t = useTenant();
  const [kind, setKind] = useState<"block" | "allow">("block");
  const [prefix, setPrefix] = useState("");
  const [ttl, setTtl] = useState<number>(86400);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [formErr, setFormErr] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const pe = checkRulePrefix(prefix);
    setErr(pe);
    if (pe) return;
    try {
      unwrap(
        await api.POST("/api/v1/tenants/{tid}/rules", {
          params: { path: { tid: t.id } },
          body: { kind, prefix: prefix.trim(), ttl_seconds: kind === "block" ? ttl : null, reason: reason.trim() || null },
        }),
      );
      setPrefix("");
      setReason("");
      setFormErr(null);
      onAdded();
    } catch (x) {
      setFormErr(errorMessage(x));
    }
  }
  return (
    <form onSubmit={submit} className="grid gap-4 sm:grid-cols-[8rem_1fr_9rem] sm:items-start" noValidate aria-label="Add a rule">
      {formErr && (
        <Alert tone="danger" className="sm:col-span-3">
          {formErr}
        </Alert>
      )}
      <Field id="rule-kind" label="Action">
        <Select value={kind} onChange={(e) => setKind(e.target.value as "block" | "allow")}>
          <option value="block">Block</option>
          <option value="allow">Allow</option>
        </Select>
      </Field>
      <Field id="rule-prefix" label="Source address or prefix" error={err}>
        <Input value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="203.0.113.7 or 203.0.113.0/24" />
      </Field>
      {kind === "block" ? (
        <Field id="rule-ttl" label="Expires after">
          <Select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
            {TTLS.map(([l, s]) => (
              <option key={s} value={s}>
                {l}
              </option>
            ))}
          </Select>
        </Field>
      ) : (
        <p className="pt-7 text-xs text-muted-fg">Allow rules never expire and always win.</p>
      )}
      <div className="sm:col-span-2">
        <Field id="rule-reason" label="Note (optional)">
          <Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} />
        </Field>
      </div>
      <div className="sm:pt-6">
        <Button type="submit" className="w-full">
          Add rule
        </Button>
      </div>
    </form>
  );
}

function RulesTable({ rules, onChange }: { rules: Rule[]; onChange: () => void }) {
  const t = useTenant();
  const [err, setErr] = useState<string | null>(null);
  if (rules.length === 0) return <Empty>No allow or block rules.</Empty>;
  return (
    <>
      {err && <Alert tone="danger">{err}</Alert>}
      <Table>
        <thead>
          <tr>
            <Th>Action</Th>
            <Th>Source</Th>
            <Th>Expires</Th>
            <Th>Note</Th>
            <Th>
              <span className="sr-only">Remove</span>
            </Th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <Td>{r.kind === "allow" ? <Badge tone="ok">allow</Badge> : <Badge tone="danger">block</Badge>}</Td>
              <Td className="font-mono">{r.prefix}</Td>
              <Td>{expiresIn(r.expires_at)}</Td>
              <Td className="max-w-48 truncate">{r.reason ?? ""}</Td>
              <Td className="text-right">
                {atLeast(t.role, "admin") && (
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label={`Remove ${r.kind} rule for ${r.prefix}`}
                    onClick={async () => {
                      try {
                        unwrap(await api.DELETE("/api/v1/tenants/{tid}/rules/{rid}", { params: { path: { tid: t.id, rid: r.id } } }));
                        onChange();
                      } catch (x) {
                        setErr(errorMessage(x));
                      }
                    }}
                  >
                    <Trash2 />
                  </Button>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </>
  );
}

function Rules() {
  const t = useTenant();
  const router = useRouter();
  const params = useSearchParams();
  const assets = useApi(async () => unwrap(await api.GET("/api/v1/tenants/{tid}/assets", { params: { path: { tid: t.id } } })), [t.id]);
  const rules = useApi(async () => unwrap(await api.GET("/api/v1/tenants/{tid}/rules", { params: { path: { tid: t.id } } })), [t.id]);
  return (
    <>
      <PageHeader title="Rules" description="Protection settings per protected IP, and allow/block lists for all of them." />
      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Protection settings</CardTitle>
            <CardDescription>Observe or mitigate, allowed services, rate limits and SYN cookies.</CardDescription>
          </CardHeader>
          <CardContent>
            <QueryView q={assets}>
              {(list) => {
                if (list.length === 0) return <Empty>Add a protected IP first.</Empty>;
                const sel = list.find((a) => String(a.id) === params.get("asset")) ?? list[0]!;
                return (
                  <div className="grid gap-5">
                    {list.length > 1 && (
                      <Field id="asset-pick" label="Protected IP">
                        <Select value={sel.id} onChange={(e) => router.replace(`/t/${t.id}/rules?asset=${e.target.value}`)}>
                          {list.map((a) => (
                            <option key={a.id} value={a.id}>
                              {hostOf(a.protected_prefix)} → {a.origin_ip}
                            </option>
                          ))}
                        </Select>
                      </Field>
                    )}
                    {list.length === 1 && <p className="font-mono text-sm">{hostOf(sel.protected_prefix)}</p>}
                    <PolicyEditor key={sel.id} asset={sel} onSaved={() => assets.reload()} />
                  </div>
                );
              }}
            </QueryView>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Allow and block lists</CardTitle>
            <CardDescription>Apply to all your protected IPs. Allowed sources skip every filter.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-6">
            {atLeast(t.role, "admin") && <RuleForm onAdded={rules.reload} />}
            <QueryView q={rules}>{(list) => <RulesTable rules={list} onChange={rules.reload} />}</QueryView>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

export default function RulesPage() {
  return (
    <Suspense>
      <Rules />
    </Suspense>
  );
}
