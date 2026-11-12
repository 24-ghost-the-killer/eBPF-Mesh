// SPDX-License-Identifier: MIT OR Apache-2.0
"use client";
import { createContext, useContext } from "react";

export type Role = "viewer" | "admin" | "owner";
const RANK: Record<Role, number> = { viewer: 0, admin: 1, owner: 2 };

export type TenantInfo = { id: number; name: string; role: Role };
export const TenantCtx = createContext<TenantInfo | null>(null);

export function useTenant(): TenantInfo {
  const t = useContext(TenantCtx);
  if (!t) throw new Error("useTenant outside a tenant page");
  return t;
}

export function atLeast(role: Role, min: Role): boolean {
  return RANK[role] >= RANK[min];
}
