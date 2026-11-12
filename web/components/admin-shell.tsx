// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { ArrowLeft, KeyRound, Radio, ShieldBan, UserCog, Users } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useSession } from "./session";
import { ThemeToggle } from "./theme-toggle";
import { Alert } from "./ui/alert";

/** Platform admin area (operators only; the API enforces it again). */
export function AdminShell({ children }: { children: React.ReactNode }) {
  const { me } = useSession();
  const path = usePathname();
  if (!me.user.is_platform_admin)
    return (
      <main id="main" className="mx-auto max-w-md p-10 text-center">
        <h1 className="text-xl font-semibold">Page not found</h1>
        <Link href="/t" className="mt-4 inline-block text-sm text-primary underline">
          Go to your account
        </Link>
      </main>
    );
  const nav = [
    { href: "/admin", label: "PoPs", icon: Radio, exact: true },
    { href: "/admin/tenants", label: "Tenants", icon: Users },
    { href: "/admin/decisions", label: "Decisions", icon: ShieldBan },
    { href: "/admin/keys", label: "Signing keys", icon: KeyRound },
    { href: "/admin/account", label: "Account", icon: UserCog },
  ];
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-card px-4 py-3">
        <div className="flex items-center gap-4">
          <span className="font-semibold">Sentinel-Edge · Platform</span>
          <nav aria-label="Admin" className="flex flex-wrap gap-1">
            {nav.map((n) => {
              const active = n.exact ? path === n.href : path.startsWith(n.href);
              return (
                <Link
                  key={n.href}
                  href={n.href}
                  aria-current={active ? "page" : undefined}
                  className={cn("flex items-center gap-2 rounded-md px-3 py-1.5 text-sm hover:bg-muted", active && "bg-muted font-medium")}
                >
                  <n.icon className="size-4" aria-hidden />
                  {n.label}
                </Link>
              );
            })}
          </nav>
        </div>
        <div className="flex items-center gap-2">
          {me.tenants.length > 0 && (
            <Link href="/t" className="flex items-center gap-1 text-sm text-muted-fg underline">
              <ArrowLeft className="size-4" aria-hidden /> Portal
            </Link>
          )}
          <ThemeToggle />
        </div>
      </header>
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 p-4 sm:p-8">
        {!me.user.mfa_enabled && (
          <Alert tone="warn" className="mb-6">
            Platform actions need two-factor authentication.{" "}
            <Link href="/admin/account" className="underline">
              Set it up on your account page
            </Link>{" "}
            first.
          </Alert>
        )}
        {children}
      </main>
    </div>
  );
}
