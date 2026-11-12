// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState } from "react";
import { ApiError, loadMe, type Me } from "@/lib/api/client";
import { ErrorState, Loading } from "./states";

const SessionCtx = createContext<{ me: Me; refresh: () => Promise<void> } | null>(null);

export function useSession() {
  const s = useContext(SessionCtx);
  if (!s) throw new Error("useSession outside <RequireSession>");
  return s;
}

/** Loads /me; sends the user to login (or the 2FA step) when needed. */
export function RequireSession({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const path = usePathname();
  const [me, setMe] = useState<Me>();
  const [error, setError] = useState<unknown>();

  const refresh = async () => {
    try {
      setMe(await loadMe());
      setError(undefined);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        const next = encodeURIComponent(path);
        router.replace(e.code === "mfa_required" ? `/login/2fa?next=${next}` : `/login?next=${next}`);
        return;
      }
      setError(e);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (error) return <ErrorState error={error} retry={refresh} />;
  if (!me) return <Loading label="Checking your session…" />;
  return <SessionCtx.Provider value={{ me, refresh }}>{children}</SessionCtx.Provider>;
}

/** Only local paths after login (no open redirects). */
export function safeNext(next: string | null | undefined, fallback = "/t"): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return fallback;
  return next;
}
