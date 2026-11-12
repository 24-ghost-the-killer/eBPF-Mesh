// SPDX-License-Identifier: MIT OR Apache-2.0
import { Shield } from "lucide-react";
import Link from "next/link";
import { ThemeToggle } from "./theme-toggle";
import { Button } from "./ui/button";

const NAV = [
  { href: "/how-it-works", label: "How it works" },
  { href: "/pricing", label: "Pricing" },
  { href: "/status", label: "Status" },
  { href: "/contact", label: "Contact" },
];

export function SiteHeader() {
  return (
    <header className="border-b border-border bg-card">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <Shield className="size-5 text-primary" aria-hidden />
          Sentinel-Edge
        </Link>
        <nav aria-label="Main" className="order-3 flex w-full flex-wrap gap-x-5 gap-y-1 text-sm sm:order-none sm:w-auto">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className="py-1 hover:text-primary hover:underline">
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <Link href="/login" className="px-2 text-sm hover:underline">
            Log in
          </Link>
          <Button asChild size="sm">
            <Link href="/signup">Get started</Link>
          </Button>
        </div>
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="mt-20 border-t border-border">
      <div className="mx-auto grid max-w-6xl gap-6 px-4 py-10 text-sm text-muted-fg sm:grid-cols-3 sm:px-6">
        <div>
          <p className="font-semibold text-fg">Sentinel-Edge</p>
          <p className="mt-2">DDoS protection at the edge. Your servers stay where they are.</p>
        </div>
        <nav aria-label="Footer" className="grid gap-2">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className="hover:underline">
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="grid content-start gap-2">
          <Link href="/signup" className="hover:underline">
            Create an account
          </Link>
          <Link href="/login" className="hover:underline">
            Log in to the portal
          </Link>
        </div>
      </div>
    </footer>
  );
}

/** Section heading + text, used across the public pages. */
export function Section({ id, title, children, className }: { id?: string; title: string; children: React.ReactNode; className?: string }) {
  return (
    <section aria-labelledby={id} className={className}>
      <h2 id={id} className="text-2xl font-semibold tracking-tight">
        {title}
      </h2>
      <div className="mt-4">{children}</div>
    </section>
  );
}

export function CallToAction() {
  return (
    <div className="mt-16 rounded-xl border border-border bg-card p-8 text-center">
      <h2 className="text-2xl font-semibold">Protect your first server in minutes</h2>
      <p className="mx-auto mt-2 max-w-xl text-muted-fg">
        Sign up, add your server, run one script. Protection starts in observe mode, so nothing is dropped until you are ready.
      </p>
      <Button asChild size="lg" className="mt-6">
        <Link href="/signup">Get started free</Link>
      </Button>
    </div>
  );
}
