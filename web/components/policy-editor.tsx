// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type Asset, errorMessage, type Policy, unwrap } from "@/lib/api/client";
import { formatServices, parseServices, type Service } from "@/lib/validate";
import { useSession } from "./session";
import { atLeast, useTenant } from "./tenant";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { Field, Input, Select } from "./ui/input";

/** Observe/mitigate, allowed services, rate limits, SYN cookies, fragments. */
export function PolicyEditor({ asset, onSaved }: { asset: Asset; onSaved: (a: Asset) => void }) {
  const t = useTenant();
  const { me } = useSession();
  const canEdit = atLeast(t.role, "admin");
  const [p, setP] = useState<Policy>(asset.policy);
  const [services, setServices] = useState(formatServices(asset.policy.services));
  const [err, setErr] = useState<string | null>(null);
  const [svcErr, setSvcErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setP(asset.policy);
    setServices(formatServices(asset.policy.services));
  }, [asset]);

  const mfa = me.user.mfa_enabled;

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setSaved(false);
    let svc: Service[];
    try {
      svc = parseServices(services);
      setSvcErr(null);
    } catch (x) {
      setSvcErr(errorMessage(x));
      return;
    }
    setBusy(true);
    try {
      const a = unwrap(
        await api.PUT("/api/v1/tenants/{tid}/assets/{aid}/policy", {
          params: { path: { tid: t.id, aid: asset.id } },
          body: { ...p, services: svc },
        }),
      );
      setSaved(true);
      onSaved(a);
    } catch (x) {
      setErr(errorMessage(x));
    } finally {
      setBusy(false);
    }
  }

  const num = (v: string) => Math.max(0, Math.min(1_000_000_000, Number.parseInt(v || "0", 10) || 0));

  return (
    <form onSubmit={save} className="grid gap-5" aria-label={`Protection for ${asset.protected_prefix}`}>
      {err && <Alert tone="danger">{err}</Alert>}
      {saved && <Alert tone="ok">Saved. The PoPs apply it within seconds.</Alert>}
      <fieldset className="grid gap-2" disabled={!canEdit}>
        <legend className="mb-1 text-sm font-medium">Mode</legend>
        <label className="flex items-start gap-2 text-sm">
          <input type="radio" name="mode" className="mt-1" checked={p.mode !== "mitigate"} onChange={() => setP({ ...p, mode: "observe" })} />
          <span>
            <strong>Observe</strong> – count what the filters would drop, deliver everything.
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="radio"
            name="mode"
            className="mt-1"
            checked={p.mode === "mitigate"}
            disabled={!mfa}
            onChange={() => setP({ ...p, mode: "mitigate" })}
          />
          <span>
            <strong>Mitigate</strong> – drop attack traffic at the PoPs.
            {!mfa && (
              <span className="block text-xs text-warn">
                Needs two-factor authentication.{" "}
                <Link className="underline" href={`/t/${t.id}/settings`}>
                  Turn it on
                </Link>
              </span>
            )}
          </span>
        </label>
      </fieldset>
      <fieldset className="grid gap-4 sm:grid-cols-2" disabled={!canEdit}>
        <div className="sm:col-span-2">
          <Field id={`svc-${asset.id}`} label="Allowed services" hint="e.g. tcp/80, tcp/443, udp/27015, icmp" error={svcErr}>
            <Input value={services} onChange={(e) => setServices(e.target.value)} />
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm sm:col-span-2">
          <input type="checkbox" checked={p.enforce_services} onChange={(e) => setP({ ...p, enforce_services: e.target.checked })} />
          Drop traffic to all other ports and protocols
        </label>
        <Field id={`pps-${asset.id}`} label="Rate limit per source (packets/s)" hint="0 = off">
          <Input type="number" min={0} value={p.pps_per_src} onChange={(e) => setP({ ...p, pps_per_src: num(e.target.value) })} />
        </Field>
        <Field id={`burst-${asset.id}`} label="Burst (packets)" hint="0 = same as the rate">
          <Input type="number" min={0} value={p.burst} onChange={(e) => setP({ ...p, burst: num(e.target.value) })} />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={p.syncookies} onChange={(e) => setP({ ...p, syncookies: e.target.checked })} />
          SYN cookies (verify TCP clients)
        </label>
        <Field id={`frag-${asset.id}`} label="IP fragments">
          <Select value={p.fragments} onChange={(e) => setP({ ...p, fragments: e.target.value })}>
            <option value="drop">Drop</option>
            <option value="allow">Allow</option>
          </Select>
        </Field>
      </fieldset>
      {canEdit && (
        <div>
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save protection settings"}
          </Button>
        </div>
      )}
    </form>
  );
}
