// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { PageHeader } from "@/components/portal-shell";
import { useSession } from "@/components/session";
import { SignInSecurity } from "@/components/sign-in-security";
import { atLeast, useTenant } from "@/components/tenant";
import { Webhooks } from "@/components/webhooks";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function SettingsPage() {
  const { me } = useSession();
  const t = useTenant();
  return (
    <>
      <PageHeader title="Settings" description="Your sign-in, two-factor authentication and notifications." />
      <div className="grid gap-6">
        <SignInSecurity />
        {atLeast(t.role, "admin") && (
          <Card>
            <CardHeader>
              <CardTitle>Attack notifications</CardTitle>
              <CardDescription>Discord, Slack, a signed HTTP webhook or email when an attack starts and ends.</CardDescription>
            </CardHeader>
            <CardContent>
              <Webhooks />
            </CardContent>
          </Card>
        )}
        <p className="text-sm text-muted-fg">Signed in as {me.user.email}.</p>
      </div>
    </>
  );
}
