// SPDX-License-Identifier: MIT OR Apache-2.0
// The overview's live graph: a rolling window of /tenants/{id}/live frames.
import type { LiveFrame } from "./api/client";

export const WINDOW = 120; // seconds shown

export type Point = { t: number; in: number; filtered: number; clean: number };

/** Appends a frame and keeps the last WINDOW points (frames arrive 1/s). */
export function pushFrame(series: Point[], f: LiveFrame, unit: "pps" | "bps"): Point[] {
  const r = f.total;
  const p: Point =
    unit === "pps"
      ? { t: f.ts, in: r.in_pps, filtered: r.filtered_pps, clean: r.clean_pps }
      : { t: f.ts, in: r.in_bps, filtered: r.filtered_bps, clean: r.clean_bps };
  const next = series.length && series[series.length - 1]!.t >= f.ts ? series.slice(0, -1) : series.slice();
  next.push(p);
  return next.length > WINDOW ? next.slice(next.length - WINDOW) : next;
}

/** ws(s)://host/api/v1/tenants/{id}/live for the current page. */
export function liveUrl(tenant: number | string, loc: Pick<Location, "protocol" | "host"> = window.location): string {
  const scheme = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${loc.host}/api/v1/tenants/${tenant}/live`;
}
