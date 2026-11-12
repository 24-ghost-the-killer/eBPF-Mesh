// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { api, errorMessage, unwrap } from "@/lib/api/client";

export default function SignupPage() {
  const [error, setError] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const email = String(f.get("email")).trim();
    const password = String(f.get("password"));
    if (password.length < 12) {
      setError("Use at least 12 characters for your password.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      unwrap(
        await api.POST("/api/v1/auth/signup", {
          body: { email, password, tenant_name: String(f.get("company")).trim() || email },
        }),
      );
      setSentTo(email);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (sentTo)
    return (
      <Card>
        <CardHeader>
          <h1 className="text-xl font-semibold">Check your email</h1>
          <CardDescription>
            If <strong>{sentTo}</strong> can be registered, we sent a link to verify it. Open it to finish signing up.
          </CardDescription>
        </CardHeader>
      </Card>
    );

  return (
    <Card>
      <CardHeader>
        <h1 className="text-xl font-semibold">Create an account</h1>
        <CardDescription>Protection starts in observe mode: nothing is dropped until you switch it on.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          {error && <Alert tone="danger">{error}</Alert>}
          <Field id="email" label="Email">
            <Input name="email" type="email" autoComplete="email" required />
          </Field>
          <Field id="password" label="Password" hint="At least 12 characters.">
            <Input name="password" type="password" autoComplete="new-password" minLength={12} required />
          </Field>
          <Field id="company" label="Company or project name">
            <Input name="company" autoComplete="organization" maxLength={100} />
          </Field>
          <Button type="submit" disabled={busy}>
            {busy ? "Creating…" : "Create account"}
          </Button>
          <p className="text-sm text-muted-fg">
            Already have an account?{" "}
            <Link className="text-primary underline" href="/login">
              Log in
            </Link>
          </p>
        </form>
      </CardContent>
    </Card>
  );
}
