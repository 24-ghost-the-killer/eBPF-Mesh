// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { startAuthentication } from "@simplewebauthn/browser";
import { KeyRound } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { safeNext } from "@/components/session";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { api, errorMessage, unwrap } from "@/lib/api/client";
import { passkeyError } from "@/lib/webauthn";

function TwoFactor() {
  const router = useRouter();
  const next = safeNext(useSearchParams().get("next"));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function withCode(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const code = String(new FormData(e.currentTarget).get("code")).replace(/\s/g, "");
    setBusy(true);
    setError(null);
    try {
      unwrap(await api.POST("/api/v1/auth/2fa/verify", { body: { code } }));
      router.push(next);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  async function withPasskey() {
    setBusy(true);
    setError(null);
    try {
      const opts = unwrap(await api.POST("/api/v1/auth/webauthn/login/start")) as { publicKey: never };
      const credential = await startAuthentication({ optionsJSON: opts.publicKey });
      unwrap(await api.POST("/api/v1/auth/webauthn/login/finish", { body: { credential } }));
      router.push(next);
    } catch (err) {
      setError(passkeyError(err));
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <h1 className="text-xl font-semibold">Two-factor authentication</h1>
        <CardDescription>Use a passkey or the 6-digit code from your authenticator app.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {error && <Alert tone="danger">{error}</Alert>}
        <Button variant="outline" onClick={withPasskey} disabled={busy}>
          <KeyRound /> Use a passkey
        </Button>
        <div className="flex items-center gap-3 text-xs text-muted-fg" aria-hidden>
          <span className="h-px flex-1 bg-border" /> or <span className="h-px flex-1 bg-border" />
        </div>
        <form onSubmit={withCode} className="grid gap-4" noValidate>
          <Field id="code" label="Authenticator code">
            <Input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} />
          </Field>
          <Button type="submit" disabled={busy}>
            Verify
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

export default function TwoFactorPage() {
  return (
    <Suspense>
      <TwoFactor />
    </Suspense>
  );
}
