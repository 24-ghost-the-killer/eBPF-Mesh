// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { PageHeader } from "@/components/portal-shell";
import { QueryView } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, unwrap } from "@/lib/api/client";

export default function TenantsPage() {
  const q = useApi(async () => unwrap(await api.GET("/api/v1/admin/tenants")), []);
  return (
    <>
      <PageHeader title="Tenants" description="Every customer account." />
      <Card>
        <CardContent className="p-0 sm:p-2">
          <QueryView q={q}>
            {(list) => (
              <Table>
                <thead>
                  <tr>
                    <Th>ID</Th>
                    <Th>Name</Th>
                    <Th>Plan</Th>
                    <Th>Status</Th>
                    <Th className="text-right">Protected IPs</Th>
                    <Th className="text-right">Members</Th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((t) => (
                    <tr key={t.id}>
                      <Td className="tabular-nums">{t.id}</Td>
                      <Td>{t.name}</Td>
                      <Td>{t.plan}</Td>
                      <Td>
                        <Badge tone={t.status === "active" ? "ok" : "warn"}>{t.status}</Badge>
                      </Td>
                      <Td className="text-right tabular-nums">{t.assets}</Td>
                      <Td className="text-right tabular-nums">{t.members}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </QueryView>
        </CardContent>
      </Card>
    </>
  );
}
