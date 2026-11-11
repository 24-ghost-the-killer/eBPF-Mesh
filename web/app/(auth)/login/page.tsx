// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { safeNext } from "@/components/session";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { api, ApiError, errorMessage, setCsrf, unwrap } from "@/lib/api/client";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const r = unwrap(
        await api.POST("/api/v1/auth/login", {
          body: { email: String(f.get("email")), password: String(f.get("password")) },
        }),
      );
      setCsrf(r.csrf_token);
      router.push(r.mfa_required ? `/login/2fa?next=${encodeURIComponent(next)}` : next);
    } catch (err) {
      setError(
        err instanceof ApiError && err.code === "email_unverified"
          ? "Verify your email address first: open the link we sent you."
          : errorMessage(err),
      );
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <h1 className="text-xl font-semibold">Log in</h1>
        <CardDescription>Manage your protected servers.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          {error && <Alert tone="danger">{error}</Alert>}
          <Field id="email" label="Email">
            <Input name="email" type="email" autoComplete="username" required />
          </Field>
          <Field id="password" label="Password">
            <Input name="password" type="password" autoComplete="current-password" required />
          </Field>
          <Button type="submit" disabled={busy}>
            {busy ? "Logging in…" : "Log in"}
          </Button>
          <div className="flex justify-between text-sm">
            <Link className="text-primary underline" href="/signup">
              Create an account
            </Link>
            <Link className="text-muted-fg underline" href="/forgot-password">
              Forgot password?
            </Link>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
