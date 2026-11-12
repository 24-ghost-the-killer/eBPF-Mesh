// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { Plus } from "lucide-react";
import Link from "next/link";
import { ModeBadge, PopStatusBadge } from "@/components/pop-status";
import { PageHeader } from "@/components/portal-shell";
import { Empty, QueryView } from "@/components/states";
import { atLeast, useTenant } from "@/components/tenant";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { useApi } from "@/components/use-api";
import { api, type Asset, unwrap } from "@/lib/api/client";
import { formatServices } from "@/lib/validate";

function Row({ a, tid }: { a: Asset; tid: number }) {
  const status = useApi(
    async () => unwrap(await api.GET("/api/v1/tenants/{tid}/assets/{aid}/status", { params: { path: { tid, aid: a.id } } })),
    [tid, a.id],
    { pollMs: 10_000 },
  );
  return (
    <tr>
      <Td>
        <Link href={`/t/${tid}/assets/${a.id}`} className="font-mono text-primary underline">
          {a.protected_prefix.replace(/\/32$/, "")}
        </Link>
      </Td>
      <Td className="font-mono">{a.origin_ip}</Td>
      <Td className="max-w-48 truncate">{formatServices(a.policy.services) || "–"}</Td>
      <Td>
        <ModeBadge mode={a.policy.mode} />
      </Td>
      <Td>
        <PopStatusBadge status={status.data} />
      </Td>
    </tr>
  );
}

export default function AssetsPage() {
  const t = useTenant();
  const q = useApi(async () => unwrap(await api.GET("/api/v1/tenants/{tid}/assets", { params: { path: { tid: t.id } } })), [t.id]);
  return (
    <>
      <PageHeader
        title="Protected IPs"
        description="Each protected IP forwards clean traffic through a tunnel to your server."
        actions={
          atLeast(t.role, "admin") && (
            <Button asChild>
              <Link href={`/t/${t.id}/assets/new`}>
                <Plus /> Protect a server
              </Link>
            </Button>
          )
        }
      />
      <Card>
        <CardContent className="p-0 sm:p-2">
          <QueryView q={q}>
            {(list) =>
              list.length === 0 ? (
                <div className="p-4">
                  <Empty>No protected IPs yet.</Empty>
                </div>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>Protected IP</Th>
                      <Th>Your server</Th>
                      <Th>Allowed services</Th>
                      <Th>Mode</Th>
                      <Th>PoPs</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((a) => (
                      <Row key={a.id} a={a} tid={t.id} />
                    ))}
                  </tbody>
                </Table>
              )
            }
          </QueryView>
        </CardContent>
      </Card>
    </>
  );
}
