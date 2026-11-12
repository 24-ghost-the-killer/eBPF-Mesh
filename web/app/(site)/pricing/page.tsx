// SPDX-License-Identifier: MIT OR Apache-2.0
import { Check } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export const metadata: Metadata = {
  title: "Pricing",
  description: "Start free with one protected IP in observe mode; upgrade when you need mitigation.",
};

const PLANS = [
  {
    name: "Free",
    tagline: "See what reaches your server",
    features: ["1 protected IP", "Observe mode: every verdict counted, nothing dropped", "Live traffic and history", "Tunnel script and tunnel test"],
    cta: { href: "/signup", label: "Start free" },
  },
  {
    name: "Basic",
    tagline: "Mitigation for small services",
    features: ["Up to 5 protected IPs", "Mitigate mode with SYN cookies, open ports and rate limits", "Allow and block lists", "Attack detection with automatic blocks", "Email and webhook alerts"],
    cta: { href: "/contact", label: "Contact us" },
    featured: true,
  },
  {
    name: "Pro",
    tagline: "For teams and larger networks",
    features: ["More protected IPs and prefixes", "Everything in Basic", "Team members with roles and API keys", "Audit log", "Priority support"],
    cta: { href: "/contact", label: "Contact us" },
  },
];

export default function Pricing() {
  return (
    <>
      <h1 className="text-4xl font-bold tracking-tight">Pricing</h1>
      <p className="mt-4 max-w-2xl text-lg text-muted-fg">
        Every plan uses the same network. Start free in observe mode; talk to us when you want to drop attacks.
      </p>
      <ul className="mt-12 grid gap-6 lg:grid-cols-3">
        {PLANS.map((p) => (
          <li
            key={p.name}
            className={`flex flex-col rounded-xl border bg-card p-6 ${p.featured ? "border-primary shadow-md" : "border-border"}`}
          >
            <h2 className="text-xl font-semibold">{p.name}</h2>
            <p className="mt-1 text-sm text-muted-fg">{p.tagline}</p>
            <ul className="mt-6 grid flex-1 content-start gap-3 text-sm">
              {p.features.map((f) => (
                <li key={f} className="flex gap-2">
                  <Check className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
                  {f}
                </li>
              ))}
            </ul>
            <Button asChild className="mt-8" variant={p.featured ? "default" : "outline"}>
              <Link href={p.cta.href}>
                {p.cta.label}
                <span className="sr-only"> about the {p.name} plan</span>
              </Link>
            </Button>
          </li>
        ))}
      </ul>
    </>
  );
}
