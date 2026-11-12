// SPDX-License-Identifier: MIT OR Apache-2.0
import type { Metadata } from "next";
import { CallToAction, Section } from "@/components/site-chrome";

export const metadata: Metadata = {
  title: "How it works",
  description: "A packet's journey through Sentinel-Edge, the platform behind it, and answers to common questions.",
};

const STEPS = [
  ["A visitor connects", "Your DNS points to your protected IP. BGP takes the visitor's packets to the nearest PoP."],
  ["The PoP checks the packet", "XDP drops malformed and bogon packets, applies your allow and block lists, open ports and rate limits, and verifies new TCP sources with SYN cookies."],
  ["Clean traffic is tunnelled", "The packet is wrapped in an IPIP header and sent to your server. Your server sees the visitor's real IP address."],
  ["Your server answers", "Replies go back through the tunnel to the nearest PoP, which checks they really come from your server and forwards them."],
  ["Attacks are handled automatically", "Analysis workers watch the traffic; during an attack they block the largest sources with signed, expiring decisions, and the portal and your webhooks tell you about it."],
];

const FAQ = [
  ["Do I have to move my server?", "No. You keep your server and provider. A small script sets up the tunnel and adds the protected IP to your server."],
  ["Will my visitors' IP addresses be hidden?", "No. Packets arrive through the tunnel unchanged, so your logs and firewall see the real client IP."],
  ["What happens on day one?", "New protected IPs start in observe mode: everything is counted but nothing is dropped. Switch to mitigate when the traffic looks right; two-factor authentication is required for that."],
  ["What about the MTU?", "The tunnel adds 20 bytes. The script sets the tunnel MTU and the PoPs clamp the TCP MSS, so connections just work."],
  ["Can a PoP failure take my site down?", "PoPs withdraw their announcement when their filter or agent is unhealthy, and traffic moves to the next PoP. Operators can drain a PoP the same way before maintenance."],
  ["Which protocols are supported?", "IPv4 and IPv6 traffic to your protected IP, TCP, UDP and ICMP; you choose which ports stay open."],
];

export default function HowItWorks() {
  return (
    <>
      <h1 className="text-4xl font-bold tracking-tight">How it works</h1>
      <p className="mt-4 max-w-2xl text-lg text-muted-fg">From the first packet of a visitor to your server&apos;s answer.</p>

      <Section id="journey" title="A packet's journey" className="mt-12">
        <ol className="grid gap-4">
          {STEPS.map(([t, d], i) => (
            <li key={t} className="flex gap-4 rounded-lg border border-border bg-card p-5">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary font-semibold text-primary-fg" aria-hidden>
                {i + 1}
              </span>
              <div>
                <h3 className="font-semibold">{t}</h3>
                <p className="mt-1 text-sm text-muted-fg">{d}</p>
              </div>
            </li>
          ))}
        </ol>
      </Section>

      <Section id="platform" title="The platform" className="mt-16">
        <figure className="overflow-x-auto rounded-xl border border-border bg-card p-4">
          <svg viewBox="0 0 760 300" className="h-auto w-full min-w-[520px]" role="img" aria-labelledby="pf-title pf-desc">
            <title id="pf-title">Platform diagram</title>
            <desc id="pf-desc">
              Visitors and attackers reach the nearest PoP over anycast. Each PoP filters with XDP and tunnels clean traffic to the
              customer&apos;s server. PoP agents send telemetry to analysis workers, which send signed decisions back. The control
              plane API stores configuration and pushes it to every PoP; the portal talks only to the API.
            </desc>
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="var(--muted-fg)" />
              </marker>
            </defs>
            {[
              [20, 40, "Visitors"],
              [20, 200, "Attackers"],
              [240, 120, "PoP: XDP + agent"],
              [500, 40, "Your server"],
              [500, 200, "Analysis workers"],
              [240, 250, "API + database"],
              [500, 120, "Portal"],
            ].map(([x, y, t]) => (
              <g key={t as string}>
                <rect x={x as number} y={y as number} width="200" height="40" rx="8" fill="var(--muted)" stroke="var(--border)" />
                <text x={(x as number) + 100} y={(y as number) + 25} textAnchor="middle" fontSize="13" fill="var(--fg)">
                  {t}
                </text>
              </g>
            ))}
            {[
              [220, 60, 240, 130],
              [220, 220, 240, 150],
              [440, 130, 500, 65],
              [440, 150, 500, 215],
              [500, 225, 440, 155],
              [340, 250, 340, 160],
              [500, 140, 440, 260],
            ].map(([x1, y1, x2, y2], i) => (
              <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--muted-fg)" strokeWidth="1.5" markerEnd="url(#arrow)" />
            ))}
          </svg>
        </figure>
      </Section>

      <Section id="faq" title="Questions" className="mt-16">
        <div className="grid gap-3">
          {FAQ.map(([q, a]) => (
            <details key={q} className="rounded-lg border border-border bg-card p-4">
              <summary className="cursor-pointer font-medium">{q}</summary>
              <p className="mt-2 text-sm text-muted-fg">{a}</p>
            </details>
          ))}
        </div>
      </Section>
      <CallToAction />
    </>
  );
}
