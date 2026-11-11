// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useParams } from "next/navigation";
import { PortalShell } from "@/components/portal-shell";
import { RequireSession } from "@/components/session";

export default function TenantLayout({ children }: { children: React.ReactNode }) {
  const { tenant } = useParams<{ tenant: string }>();
  return (
    <RequireSession>
      <PortalShell tenantParam={tenant}>{children}</PortalShell>
    </RequireSession>
  );
}
