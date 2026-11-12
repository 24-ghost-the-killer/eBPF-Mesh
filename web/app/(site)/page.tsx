// SPDX-License-Identifier: MIT OR Apache-2.0
import { Activity, Gauge, Globe2, Lock, ShieldCheck, Zap } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { PopMap } from "@/components/pop-map";
import { CallToAction, Section } from "@/components/site-chrome";
import { Button } from "@/components/ui/button";

export const metadata: Metadata = {
  title: "DDoS protection at the edge",
  description:
    "Sentinel-Edge filters attack traffic at anycast PoPs with XDP and tunnels clean traffic to your own servers, with the real client IP.",
};

const THREATS = [
  { icon: Zap, title: "SYN floods", text: "Every new TCP source proves itself with a SYN cookie before it reaches you." },
  { icon: Activity, title: "UDP and ICMP floods", text: "Only the ports you need stay open; floods are dropped at the edge." },
  { icon: Gauge, title: "Volumetric attacks", text: "Per-source rate limits and automatic blocks of the largest sources, always with an expiry." },
  { icon: ShieldCheck, title: "Spoofed and bogus traffic", text: "Private, reserved and malformed packets never leave the PoP." },
];

export default function Home() {
  return (
    <>
      <section className="grid items-center gap-10 lg:grid-cols-2">
        <div>
          <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">DDoS protection that keeps your servers where they are</h1>
          <p className="mt-5 text-lg text-muted-fg">
            Traffic to your protected IP lands at the nearest of our PoPs. Attacks are dropped there, in the network card&apos;s
            driver, before they cost anything. Clean traffic travels through a tunnel to your own server, with the real client
            IP.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild size="lg">
              <Link href="/signup">Get started</Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link href="/how-it-works">How it works</Link>
            </Button>
          </div>
        </div>
        <PopMap />
      </section>

      <Section id="threats" title="What it protects against" className="mt-20">
        <ul className="grid gap-4 sm:grid-cols-2">
          {THREATS.map((t) => (
            <li key={t.title} className="rounded-lg border border-border bg-card p-5">
              <t.icon className="size-5 text-primary" aria-hidden />
              <h3 className="mt-3 font-semibold">{t.title}</h3>
              <p className="mt-1 text-sm text-muted-fg">{t.text}</p>
            </li>
          ))}
        </ul>
      </Section>

      <Section id="anycast" title="How anycast spreads the load" className="mt-20">
        <div className="grid gap-6 md:grid-cols-3">
          <div>
            <Globe2 className="size-5 text-primary" aria-hidden />
            <h3 className="mt-2 font-semibold">One address, many places</h3>
            <p className="mt-1 text-sm text-muted-fg">
              Every PoP announces the same prefix over BGP. The internet routes each visitor, and each attacker, to the nearest
              one, so a large attack is split across all of them.
            </p>
          </div>
          <div>
            <Lock className="size-5 text-primary" aria-hidden />
            <h3 className="mt-2 font-semibold">Filtered before the kernel</h3>
            <p className="mt-1 text-sm text-muted-fg">
              An XDP program checks every packet against your policy: allow and block lists, open ports, rate limits and SYN
              cookies. You start in observe mode and switch to dropping when you are ready.
            </p>
          </div>
          <div>
            <ShieldCheck className="size-5 text-primary" aria-hidden />
            <h3 className="mt-2 font-semibold">Healthy PoPs only</h3>
            <p className="mt-1 text-sm text-muted-fg">
              A PoP that loses its filter or its agent stops announcing within seconds, and traffic moves to the next one without
              dropping your visitors.
            </p>
          </div>
        </div>
      </Section>

      <CallToAction />
    </>
  );
}
