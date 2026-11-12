// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { errorMessage } from "@/lib/api/client";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-2 py-6 text-sm text-muted-fg">
      <span className="size-4 animate-spin rounded-full border-2 border-border border-t-primary" aria-hidden />
      {label}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  return (
    <Alert tone="danger" className="flex flex-wrap items-center justify-between gap-3">
      <span>{errorMessage(error)}</span>
      {retry && (
        <Button size="sm" variant="outline" onClick={retry}>
          Try again
        </Button>
      )}
    </Alert>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="rounded-md border border-dashed border-border p-6 text-center text-sm text-muted-fg">{children}</div>;
}

/** Loading / error / content for one query. */
export function QueryView<T>({
  q,
  children,
}: {
  q: { data: T | undefined; error: unknown; loading: boolean; reload: () => void };
  children: (data: T) => React.ReactNode;
}) {
  if (q.error && q.data === undefined) return <ErrorState error={q.error} retry={q.reload} />;
  if (q.data === undefined) return <Loading />;
  return <>{children(q.data)}</>;
}
