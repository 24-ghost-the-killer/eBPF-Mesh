// SPDX-License-Identifier: MIT OR Apache-2.0
import { Shield } from "lucide-react";
import Link from "next/link";
import { ThemeToggle } from "@/components/theme-toggle";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="flex items-center justify-between px-4 py-3 sm:px-8">
        <Link href="/t" className="flex items-center gap-2 font-semibold">
          <Shield className="size-5 text-primary" aria-hidden />
          Sentinel-Edge
        </Link>
        <ThemeToggle />
      </header>
      <main id="main" className="flex flex-1 items-start justify-center px-4 pb-16 pt-6 sm:pt-16">
        <div className="w-full max-w-sm">{children}</div>
      </main>
    </div>
  );
}
