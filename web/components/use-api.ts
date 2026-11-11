// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { useCallback, useEffect, useRef, useState } from "react";

export type Query<T> = {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  reload: () => void;
};

/** Runs `fn` on mount and whenever `deps` change; `reload` runs it again. */
export function useApi<T>(fn: () => Promise<T>, deps: unknown[], opts: { pollMs?: number } = {}): Query<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    let live = true;
    setLoading((l) => l || data === undefined);
    fnRef
      .current()
      .then((d) => {
        if (live) {
          setData(d);
          setError(undefined);
        }
      })
      .catch((e) => live && setError(e))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  useEffect(() => {
    if (!opts.pollMs) return;
    const id = setInterval(() => setTick((t) => t + 1), opts.pollMs);
    return () => clearInterval(id);
  }, [opts.pollMs]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}
