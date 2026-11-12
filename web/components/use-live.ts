// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useEffect, useState } from "react";
import type { LiveFrame } from "@/lib/api/client";
import { liveUrl, type Point, pushFrame } from "@/lib/live";

export type LiveState = {
  status: "connecting" | "open" | "reconnecting";
  last: LiveFrame | null;
  pps: Point[];
  bps: Point[];
};

/** Subscribes to /tenants/{id}/live; reconnects with backoff. */
export function useLive(tenant: number): LiveState {
  const [s, setS] = useState<LiveState>({ status: "connecting", last: null, pps: [], bps: [] });
  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const open = () => {
      ws = new WebSocket(liveUrl(tenant));
      ws.onopen = () => {
        retry = 0;
        setS((p) => ({ ...p, status: "open" }));
      };
      ws.onmessage = (ev) => {
        try {
          const f = JSON.parse(String(ev.data)) as LiveFrame;
          setS((p) => ({ status: "open", last: f, pps: pushFrame(p.pps, f, "pps"), bps: pushFrame(p.bps, f, "bps") }));
        } catch {}
      };
      ws.onclose = () => {
        if (stopped) return;
        setS((p) => ({ ...p, status: "reconnecting" }));
        timer = setTimeout(open, Math.min(30_000, 1000 * 2 ** retry++));
      };
    };
    open();
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [tenant]);
  return s;
}
