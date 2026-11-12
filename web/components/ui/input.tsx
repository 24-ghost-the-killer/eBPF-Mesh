// SPDX-License-Identifier: MIT OR Apache-2.0
import * as React from "react";
import { cn } from "@/lib/utils";

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "flex h-9 w-full rounded-md border border-border bg-card px-3 py-1 text-sm placeholder:text-muted-fg disabled:opacity-50 aria-[invalid=true]:border-danger",
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("text-sm font-medium", className)} {...props} />;
}

export function Select({ className, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn("flex h-9 w-full rounded-md border border-border bg-card px-3 py-1 text-sm", className)}
      {...props}
    />
  );
}

/** Label + control + hint/error, wired up for screen readers. */
export function Field({
  id,
  label,
  hint,
  error,
  children,
}: {
  id: string;
  label: string;
  hint?: React.ReactNode;
  error?: string | null;
  children: React.ReactElement<{ "aria-describedby"?: string; "aria-invalid"?: boolean; id?: string }>;
}) {
  const describedBy = [hint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") || undefined;
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {React.cloneElement(children, { id, "aria-describedby": describedBy, "aria-invalid": !!error })}
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted-fg">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
