// SPDX-License-Identifier: MIT OR Apache-2.0
import { SiteFooter, SiteHeader } from "@/components/site-chrome";

export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 pt-10 sm:px-6 sm:pt-16">
        {children}
      </main>
      <SiteFooter />
    </div>
  );
}
