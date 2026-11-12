// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { RequireSession, useSession } from "@/components/session";
import { Empty, Loading } from "@/components/states";

function Pick() {
  const { me } = useSession();
  const router = useRouter();
  const first = me.tenants[0];
  // Operators often belong to no tenant: their home is the admin area.
  const admin = !first && me.user.is_platform_admin;
  useEffect(() => {
    if (first) router.replace(`/t/${first.id}`);
    else if (admin) router.replace("/admin");
  }, [first, admin, router]);
  if (first) return <Loading label="Opening your account…" />;
  if (admin) return <Loading label="Opening the platform admin area…" />;
  return <Empty>Your user is not a member of any account.</Empty>;
}

export default function TenantPicker() {
  return (
    <main id="main" className="mx-auto max-w-lg p-8">
      <RequireSession>
        <Pick />
      </RequireSession>
    </main>
  );
}
