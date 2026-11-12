// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { PageHeader } from "@/components/portal-shell";
import { useSession } from "@/components/session";
import { SignInSecurity } from "@/components/sign-in-security";

export default function AdminAccountPage() {
  const { me } = useSession();
  return (
    <>
      <PageHeader title="Account" description={`Sign-in security for ${me.user.email}.`} />
      <div className="grid gap-6">
        <SignInSecurity />
      </div>
    </>
  );
}
