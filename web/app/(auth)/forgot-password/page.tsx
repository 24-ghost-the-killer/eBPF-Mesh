// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { api, errorMessage, unwrap } from "@/lib/api/client";

export default function ForgotPage() {
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    try {
      unwrap(
        await api.POST("/api/v1/auth/reset-password", {
          body: { email: String(new FormData(e.currentTarget).get("email")) },
        }),
      );
      setDone(true);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Card>
      <CardHeader>
        <h1 className="text-xl font-semibold">Reset your password</h1>
        <CardDescription>We send a link that is valid for one hour.</CardDescription>
      </CardHeader>
      <CardContent>
        {done ? (
          <Alert tone="ok">If an account exists for that address, a reset link is on its way.</Alert>
        ) : (
          <form onSubmit={submit} className="grid gap-4" noValidate>
            {error && <Alert tone="danger">{error}</Alert>}
            <Field id="email" label="Email">
              <Input name="email" type="email" autoComplete="email" required />
            </Field>
            <Button type="submit">Send link</Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
