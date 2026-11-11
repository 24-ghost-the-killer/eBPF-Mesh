// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { startRegistration } from "@simplewebauthn/browser";
import { KeyRound, Trash2 } from "lucide-react";
import QRCode from "qrcode";
import { useState } from "react";
import { PageHeader } from "@/components/portal-shell";
import { useSession } from "@/components/session";
import { Empty, QueryView } from "@/components/states";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, errorMessage, loadMe, unwrap } from "@/lib/api/client";
import { dateTime } from "@/lib/format";
import { passkeyError } from "@/lib/webauthn";

function Totp({ onChange }: { onChange: () => Promise<void> }) {
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  async function start() {
    setErr(null);
    try {
      const s = unwrap(await api.POST("/api/v1/auth/2fa/setup"));
      setSetup({ secret: s.secret, qr: await QRCode.toDataURL(s.otpauth_url, { margin: 1, width: 180 }) });
    } catch (e) {
      setErr(errorMessage(e));
    }
  }
  async function enable(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      unwrap(await api.POST("/api/v1/auth/2fa/enable", { body: { code: code.replace(/\s/g, "") } }));
      setDone(true);
      setSetup(null);
      await loadMe();
      await onChange();
    } catch (x) {
      setErr(errorMessage(x));
    }
  }
  if (done) return <Alert tone="ok">Authenticator app enabled. Other sessions were logged out.</Alert>;
  return (
    <div className="grid gap-4">
      {err && <Alert tone="danger">{err}</Alert>}
      {!setup ? (
        <div>
          <Button variant="outline" onClick={start}>
            Set up an authenticator app
          </Button>
        </div>
      ) : (
        <form onSubmit={enable} className="grid gap-4 sm:grid-cols-[auto_1fr] sm:items-start">
          {/* data: URL generated locally; allowed by the CSP's img-src */}
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={setup.qr} alt="QR code for your authenticator app" width={180} height={180} className="rounded border border-border bg-white" />
          <div className="grid gap-3">
            <p className="text-sm">
              Scan the code, or enter this key manually:{" "}
              <code className="break-all rounded bg-muted px-1 font-mono" data-testid="totp-secret">
                {setup.secret}
              </code>
            </p>
            <Field id="totp-code" label="Code from the app">
              <Input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={7} />
            </Field>
            <div>
              <Button type="submit">Turn on</Button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}

function Passkeys({ onChange }: { onChange: () => Promise<void> }) {
  const list = useApi(async () => unwrap(await api.GET("/api/v1/auth/webauthn/credentials")), []);
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setOk(null);
    try {
      const opts = unwrap(await api.POST("/api/v1/auth/webauthn/register/start")) as { publicKey: never };
      const credential = await startRegistration({ optionsJSON: opts.publicKey });
      const pk = unwrap(
        await api.POST("/api/v1/auth/webauthn/register/finish", { body: { name: name.trim() || "Passkey", credential } }),
      );
      setOk(`Passkey "${pk.name}" added.`);
      setName("");
      list.reload();
      await loadMe();
      await onChange();
    } catch (x) {
      setErr(passkeyError(x));
    }
  }
  return (
    <div className="grid gap-4">
      {err && <Alert tone="danger">{err}</Alert>}
      {ok && <Alert tone="ok">{ok}</Alert>}
      <QueryView q={list}>
        {(keys) =>
          keys.length === 0 ? (
            <Empty>No passkeys yet.</Empty>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Added</Th>
                  <Th>Last used</Th>
                  <Th>
                    <span className="sr-only">Remove</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.id}>
                    <Td>{k.name}</Td>
                    <Td>{dateTime(k.created_at)}</Td>
                    <Td>{dateTime(k.last_used_at)}</Td>
                    <Td className="text-right">
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Remove passkey ${k.name}`}
                        onClick={async () => {
                          try {
                            unwrap(await api.DELETE("/api/v1/auth/webauthn/credentials/{id}", { params: { path: { id: k.id } } }));
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
      <form onSubmit={add} className="flex flex-wrap items-end gap-3">
        <div className="min-w-48 flex-1">
          <Field id="passkey-name" label="Name for the new passkey">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Laptop" maxLength={64} />
          </Field>
        </div>
        <Button type="submit">
          <KeyRound /> Add a passkey
        </Button>
      </form>
    </div>
  );
}

export default function SettingsPage() {
  const { me, refresh } = useSession();
  return (
    <>
      <PageHeader title="Settings" description="Your sign-in and two-factor authentication." />
      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Two-factor authentication
              {me.user.mfa_enabled ? <Badge tone="ok">On</Badge> : <Badge tone="warn">Off</Badge>}
            </CardTitle>
            <CardDescription>
              Required before you can switch a protected IP to mitigate mode. Use a passkey, an authenticator app, or both.
            </CardDescription>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Passkeys</CardTitle>
            <CardDescription>Sign in with your device&apos;s fingerprint, face or PIN, or a security key.</CardDescription>
          </CardHeader>
          <CardContent>
            <Passkeys onChange={refresh} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Authenticator app</CardTitle>
            <CardDescription>Time-based 6-digit codes (TOTP).</CardDescription>
          </CardHeader>
          <CardContent>
            <Totp onChange={refresh} />
          </CardContent>
        </Card>
        <p className="text-sm text-muted-fg">Signed in as {me.user.email}.</p>
      </div>
    </>
  );
}
