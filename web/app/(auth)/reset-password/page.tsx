// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { api, errorMessage, unwrap } from "@/lib/api/client";

function Reset() {
  const token = useSearchParams().get("token") ?? "";
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const password = String(new FormData(e.currentTarget).get("password"));
    try {
      unwrap(await api.POST("/api/v1/auth/reset-password/confirm", { body: { token, password } }));
      setDone(true);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Card>
      <CardHeader>
        <h1 className="text-xl font-semibold">Choose a new password</h1>
      </CardHeader>
      <CardContent>
        {done ? (
          <div className="grid gap-3">
            <Alert tone="ok">Password changed. All other sessions were logged out.</Alert>
            <Link className="text-sm text-primary underline" href="/login">
              Log in
            </Link>
          </div>
        ) : (
          <form onSubmit={submit} className="grid gap-4" noValidate>
            {error && <Alert tone="danger">{error}</Alert>}
            <Field id="password" label="New password" hint="At least 12 characters.">
              <Input name="password" type="password" autoComplete="new-password" minLength={12} required />
            </Field>
            <Button type="submit">Change password</Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}

export default function ResetPage() {
  return (
    <Suspense>
      <Reset />
    </Suspense>
  );
}
