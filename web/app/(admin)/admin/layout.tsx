// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { AdminShell } from "@/components/admin-shell";
import { RequireSession } from "@/components/session";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <RequireSession>
      <AdminShell>{children}</AdminShell>
    </RequireSession>
  );
}
