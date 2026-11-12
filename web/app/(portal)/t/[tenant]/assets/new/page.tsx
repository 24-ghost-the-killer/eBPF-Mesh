// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { PageHeader } from "@/components/portal-shell";
import { atLeast, useTenant } from "@/components/tenant";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { api, errorMessage, unwrap } from "@/lib/api/client";
import { isIPv4, parseServices } from "@/lib/validate";

export default function NewAsset() {
  const t = useTenant();
  const router = useRouter();
  const [origin, setOrigin] = useState("");
  const [services, setServices] = useState("tcp/80, tcp/443");
  const [errors, setErrors] = useState<{ origin?: string; services?: string; form?: string }>({});
  const [busy, setBusy] = useState(false);

  if (!atLeast(t.role, "admin")) return <Alert tone="warn">Only admins and owners can add protected IPs.</Alert>;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const errs: typeof errors = {};
    if (!isIPv4(origin.trim())) errs.origin = "Enter your server's public IPv4 address.";
    let svc: ReturnType<typeof parseServices> = [];
    try {
      svc = parseServices(services);
    } catch (err) {
      errs.services = errorMessage(err);
    }
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      const a = unwrap(
        await api.POST("/api/v1/tenants/{tid}/assets", {
          params: { path: { tid: t.id } },
          body: { origin_ip: origin.trim(), services: svc },
        }),
      );
      router.push(`/t/${t.id}/assets/${a.id}?new=1`);
    } catch (err) {
      setErrors({ form: errorMessage(err) });
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Protect a server" description="Step 1 of 4: tell us where clean traffic should go." />
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle>Your server</CardTitle>
          <CardDescription>
            You get a protected IP from our anycast range. Traffic to it is filtered at the nearest PoP and the clean part
            arrives at your server through an IPIP tunnel, with the real client IP.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid gap-4" noValidate>
            {errors.form && <Alert tone="danger">{errors.form}</Alert>}
            <Field id="origin" label="Server IP (origin)" hint="The public IPv4 address of your server." error={errors.origin}>
              <Input value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder="192.0.2.10" inputMode="decimal" />
            </Field>
            <Field
              id="services"
              label="Ports that must stay open"
              hint="Comma separated, e.g. tcp/80, tcp/443, udp/27015, icmp. Only enforced once you turn on service filtering."
              error={errors.services}
            >
              <Input value={services} onChange={(e) => setServices(e.target.value)} />
            </Field>
            <Button type="submit" disabled={busy}>
              {busy ? "Allocating…" : "Get a protected IP"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </>
  );
}
