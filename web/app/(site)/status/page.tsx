// SPDX-License-Identifier: MIT OR Apache-2.0
import type { Metadata } from "next";
import { StatusTable } from "@/components/status-table";
import { STATUS_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Status",
  description: "Live status of every point of presence.",
};

export default function Status() {
  return (
    <>
      <h1 className="text-4xl font-bold tracking-tight">Status</h1>
      <p className="mt-4 max-w-2xl text-lg text-muted-fg">Live status of every point of presence, refreshed every 15 seconds.</p>
      {STATUS_URL && (
        <p className="mt-2 text-sm">
          If this site is unreachable, our{" "}
          <a className="text-primary underline" href={STATUS_URL}>
            independent status page
          </a>{" "}
          is hosted separately and lists incidents.
        </p>
      )}
      <div className="mt-8">
        <StatusTable />
      </div>
    </>
  );
}
