// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { api, unwrap } from "@/lib/api/client";
import { dateTime } from "@/lib/format";
import { ErrorState, Loading } from "./states";
import { Badge } from "./ui/badge";
import { Table, Td, Th } from "./ui/table";
import { useApi } from "./use-api";

export function StatusTable() {
  const q = useApi(async () => unwrap(await api.GET("/api/v1/status")), [], { pollMs: 15_000 });
  if (q.error && !q.data) return <ErrorState error={q.error} retry={q.reload} />;
  if (!q.data) return <Loading />;
  const pops = q.data.pops;
  const up = pops.filter((p) => p.status === "up").length;
  return (
    <div className="grid gap-4">
      <p role="status" className="text-lg font-medium" data-testid="status-summary">
        {pops.length === 0 ? "No PoP has reported yet." : up === pops.length ? "All PoPs operational" : `${up} of ${pops.length} PoPs operational`}
      </p>
      {pops.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>PoP</Th>
              <Th>Region</Th>
              <Th>Status</Th>
              <Th>Last report</Th>
            </tr>
          </thead>
          <tbody>
            {pops.map((p) => (
              <tr key={p.id}>
                <Td className="font-mono">{p.id}</Td>
                <Td>{p.region}</Td>
                <Td>
                  <Badge tone={p.status === "up" ? "ok" : p.status === "draining" ? "warn" : "danger"}>{p.status}</Badge>
                </Td>
                <Td>{dateTime(p.last_seen)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
