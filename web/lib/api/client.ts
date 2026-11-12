// SPDX-License-Identifier: MIT OR Apache-2.0
// The only way the web app talks to the platform: the API, same origin,
// typed from docs/openapi.json (pnpm gen:api).
import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";

export type Schemas = components["schemas"];
export type Asset = Schemas["AssetView"];
export type Policy = Schemas["PolicyView"];
export type AssetStatus = Schemas["AssetStatus"];
export type Rule = Schemas["RuleView"];
export type Me = Schemas["MeResp"];
export type TunnelTest = Schemas["TunnelTest"];
export type LiveFrame = Schemas["LiveFrame"];
export type Rates = Schemas["Rates"];
export type Passkey = Schemas["PasskeyView"];
export type ApiErrorBody = Schemas["ErrorBody"];
export type Attack = Schemas["AttackView"];
export type AttackDetail = Schemas["AttackDetail"];
export type ActiveAttack = Schemas["ActiveAttack"];
export type Webhook = Schemas["WebhookView"];

// The CSRF token comes with the login response and GET /me. It is kept in
// sessionStorage so a reload during the 2FA step still has it (it is not a
// secret from same-origin scripts; the session cookie itself is HttpOnly).
let csrf: string | null = null;
export function setCsrf(t: string | null | undefined) {
  csrf = t ?? null;
  try {
    if (csrf) sessionStorage.setItem("csrf", csrf);
    else sessionStorage.removeItem("csrf");
  } catch {}
}
function currentCsrf(): string | null {
  if (csrf) return csrf;
  try {
    csrf = sessionStorage.getItem("csrf");
  } catch {}
  return csrf;
}

const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    const t = currentCsrf();
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method) && t) {
      request.headers.set("x-csrf-token", t);
    }
    return request;
  },
};

export const api = createClient<paths>({ baseUrl: "", credentials: "same-origin" });
api.use(csrfMiddleware);

/** An API error as the UI shows it. */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Unwraps an openapi-fetch result: data, or throws ApiError. */
export function unwrap<T>(r: { data?: T; error?: unknown; response: Response }): T {
  if (r.error !== undefined || !r.response.ok) {
    const e = (r.error ?? {}) as Partial<ApiErrorBody>;
    throw new ApiError(
      r.response.status,
      e.error ?? "http_" + r.response.status,
      e.message ?? r.response.statusText ?? "request failed",
    );
  }
  return r.data as T;
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return "Something went wrong.";
}

/** Fetches /me and refreshes the CSRF token. */
export async function loadMe(): Promise<Me> {
  const me = unwrap(await api.GET("/api/v1/me"));
  setCsrf(me.csrf_token);
  return me;
}
