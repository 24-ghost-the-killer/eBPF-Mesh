// SPDX-License-Identifier: MIT OR Apache-2.0
import type { Metadata } from "next";
import { headers } from "next/headers";
import { THEME_SCRIPT } from "@/components/theme-toggle";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Sentinel-Edge", template: "%s · Sentinel-Edge" },
  description: "DDoS protection for your servers: filtering at the edge, clean traffic through a tunnel.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="min-h-dvh antialiased">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-card focus:px-3 focus:py-2">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
