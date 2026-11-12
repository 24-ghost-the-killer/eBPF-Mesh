// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { Loading } from "@/components/states";
import { Alert } from "@/components/ui/alert";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { api, errorMessage, unwrap } from "@/lib/api/client";

function Verify() {
  const token = useSearchParams().get("token");
  const [state, setState] = useState<"busy" | "ok" | string>("busy");
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return; // the token is single use (StrictMode runs effects twice)
    started.current = true;
    if (!token) {
      setState("This link is incomplete.");
      return;
    }
    api
      .POST("/api/v1/auth/verify-email", { body: { token } })
      .then((r) => {
        unwrap(r);
        setState("ok");
      })
      .catch((e) => setState(errorMessage(e)));
  }, [token]);

  return (
    <Card>
      <CardHeader>
        <h1 className="text-xl font-semibold">Verify your email</h1>
      </CardHeader>
      <CardContent className="grid gap-4">
        {state === "busy" && <Loading label="Verifying…" />}
        {state === "ok" && (
          <>
            <Alert tone="ok">Your email address is verified.</Alert>
            <Link href="/login" className="text-sm text-primary underline">
              Log in
            </Link>
          </>
        )}
        {state !== "busy" && state !== "ok" && <Alert tone="danger">{state}</Alert>}
      </CardContent>
    </Card>
  );
}

export default function VerifyPage() {
  return (
    <Suspense>
      <Verify />
    </Suspense>
  );
}
