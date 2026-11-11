// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Activity, ListFilter, LogOut, Server, Settings, Shield } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { api, setCsrf } from "@/lib/api/client";
import { cn } from "@/lib/utils";
import { useSession } from "./session";
import { type Role, TenantCtx } from "./tenant";
import { ThemeToggle } from "./theme-toggle";
import { Button } from "./ui/button";

export function PortalShell({ tenantParam, children }: { tenantParam: string; children: React.ReactNode }) {
  const { me } = useSession();
  const path = usePathname();
  const router = useRouter();
  // Only tenants listed in /me exist for this user: never ask the API about
  // others (and the API would answer 404 anyway).
  const t = me.tenants.find((x) => String(x.id) === tenantParam);
  if (!t)
    return (
      <main id="main" className="mx-auto max-w-md p-10 text-center">
        <h1 className="text-xl font-semibold">Page not found</h1>
        <p className="mt-2 text-sm text-muted-fg">It may have moved, or you may not have access to it.</p>
        <Link href="/t" className="mt-4 inline-block text-sm text-primary underline">
          Go to your account
        </Link>
      </main>
    );
  const base = `/t/${t.id}`;
  const nav = [
    { href: base, label: "Overview", icon: Activity, exact: true },
    { href: `${base}/assets`, label: "Protected IPs", icon: Server },
    { href: `${base}/rules`, label: "Rules", icon: ListFilter },
    { href: `${base}/settings`, label: "Settings", icon: Settings },
  ];
  async function logout() {
    await api.POST("/api/v1/auth/logout").catch(() => undefined);
    setCsrf(null);
    router.replace("/login");
  }
  return (
    <TenantCtx.Provider value={{ id: t.id, name: t.name, role: t.role as Role }}>
      <div className="flex min-h-dvh flex-col md:flex-row">
        <aside className="border-b border-border bg-card md:w-60 md:shrink-0 md:border-b-0 md:border-r">
          <div className="flex items-center justify-between px-4 py-3">
            <Link href={base} className="flex items-center gap-2 font-semibold">
              <Shield className="size-5 text-primary" aria-hidden />
              Sentinel-Edge
            </Link>
            <ThemeToggle />
          </div>
          <p className="truncate px-4 pb-2 text-xs text-muted-fg" title={t.name}>
            {t.name} · {t.role}
          </p>
          <nav aria-label="Portal" className="flex flex-wrap gap-1 px-2 pb-2 md:flex-col md:flex-nowrap">
            {nav.map((n) => {
              const active = n.exact ? path === n.href : path.startsWith(n.href);
              return (
                <Link
                  key={n.href}
                  href={n.href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm hover:bg-muted",
                    active && "bg-muted font-medium",
                  )}
                >
                  <n.icon className="size-4" aria-hidden />
                  {n.label}
                </Link>
              );
            })}
          </nav>
          <div className="hidden px-4 py-3 text-xs text-muted-fg md:block">
            <p className="truncate" title={me.user.email}>
              {me.user.email}
            </p>
            <Button variant="ghost" size="sm" className="mt-1 -ml-3" onClick={logout}>
              <LogOut /> Log out
            </Button>
          </div>
        </aside>
        <main id="main" className="min-w-0 flex-1 p-4 sm:p-8">
          {children}
          <div className="mt-10 md:hidden">
            <Button variant="outline" size="sm" onClick={logout}>
              <LogOut /> Log out
            </Button>
          </div>
        </main>
      </div>
    </TenantCtx.Provider>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-fg">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
