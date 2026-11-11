// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Send, Trash2 } from "lucide-react";
import { useState } from "react";
import { api, errorMessage, unwrap } from "@/lib/api/client";
import { dateTime } from "@/lib/format";
import { CopyButton } from "./copy";
import { Empty, QueryView } from "./states";
import { useTenant } from "./tenant";
import { Alert } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Field, Input, Select } from "./ui/input";
import { Table, Td, Th } from "./ui/table";
import { useApi } from "./use-api";

const PLACEHOLDER: Record<string, string> = {
  discord: "https://discord.com/api/webhooks/…",
  slack: "https://hooks.slack.com/services/…",
  http: "https://ops.example.org/sentinel",
  email: "ops@example.org",
};

/** Attack notifications: Discord, Slack, signed HTTP, email. */
export function Webhooks() {
  const t = useTenant();
  const list = useApi(async () => unwrap(await api.GET("/api/v1/tenants/{tid}/webhooks", { params: { path: { tid: t.id } } })), [t.id]);
  const [kind, setKind] = useState("http");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [tested, setTested] = useState<Record<number, string>>({});

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setSecret(null);
    try {
      const r = unwrap(
        await api.POST("/api/v1/tenants/{tid}/webhooks", {
          params: { path: { tid: t.id } },
          body: { kind, name: name.trim(), target: target.trim() },
        }),
      );
      setSecret(r.secret ?? null);
      setTarget("");
      setName("");
      list.reload();
    } catch (x) {
      setErr(errorMessage(x));
    }
  }

  return (
    <div className="grid gap-4">
      {err && <Alert tone="danger">{err}</Alert>}
      {secret && (
        <Alert tone="warn" className="grid gap-2">
          <span>
            Signing secret (shown once): verify the <code className="font-mono">X-Sentinel-Signature</code> header, an HMAC-SHA256
            of <code className="font-mono">timestamp.body</code>, with it.
          </span>
          <code className="break-all font-mono text-xs" data-testid="webhook-secret">
            {secret}
          </code>
          <div>
            <CopyButton text={secret} label="Copy secret" />
          </div>
        </Alert>
      )}
      <QueryView q={list}>
        {(hooks) =>
          hooks.length === 0 ? (
            <Empty>No notifications set up.</Empty>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Kind</Th>
                  <Th>Target</Th>
                  <Th>Last delivery</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {hooks.map((h) => (
                  <tr key={h.id}>
                    <Td>
                      <Badge>{h.kind}</Badge> {h.name}
                    </Td>
                    <Td className="max-w-64 truncate font-mono text-xs" title={h.target}>
                      {h.target}
                    </Td>
                    <Td className="text-xs">
                      {tested[h.id] ?? (h.last_status ? `${h.last_status} · ${dateTime(h.last_at)}` : "never")}
                    </Td>
                    <Td className="whitespace-nowrap text-right">
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Send a test to ${h.target}`}
                        onClick={async () => {
                          try {
                            const r = unwrap(
                              await api.POST("/api/v1/tenants/{tid}/webhooks/{wid}/test", { params: { path: { tid: t.id, wid: h.id } } }),
                            );
                            setTested({ ...tested, [h.id]: r.ok ? `test ok: ${r.status}` : `test failed: ${r.status}` });
                          } catch (x) {
                            setErr(errorMessage(x));
                          }
                        }}
                      >
                        <Send />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Remove notification to ${h.target}`}
                        onClick={async () => {
                          try {
                            unwrap(await api.DELETE("/api/v1/tenants/{tid}/webhooks/{wid}", { params: { path: { tid: t.id, wid: h.id } } }));
                            list.reload();
                          } catch (x) {
                            setErr(errorMessage(x));
                          }
                        }}
                      >
                        <Trash2 />
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )
        }
      </QueryView>
      <form onSubmit={add} className="grid gap-4 sm:grid-cols-[9rem_10rem_1fr_auto] sm:items-end" aria-label="Add a notification">
        <Field id="wh-kind" label="Kind">
          <Select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="http">HTTP (signed)</option>
            <option value="discord">Discord</option>
            <option value="slack">Slack</option>
            <option value="email">Email</option>
          </Select>
        </Field>
        <Field id="wh-name" label="Name (optional)">
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />
        </Field>
        <Field id="wh-target" label={kind === "email" ? "Email address" : "Webhook URL"}>
          <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={PLACEHOLDER[kind]} />
        </Field>
        <Button type="submit">Add</Button>
      </form>
    </div>
  );
}
