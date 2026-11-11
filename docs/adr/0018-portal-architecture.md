# 0018 Portal architecture: same origin, client rendering, generated client

**Status:** Accepted (phase 6)

**Context.** The spec asks for a Next.js portal that talks only to the API,
uses an OpenAPI-generated client, keeps sessions in HttpOnly SameSite=Strict
cookies with CSRF tokens, and sends security headers (CSP, HSTS,
X-Frame-Options, Referrer-Policy). Passkeys are bound to a domain.

**Decision.**
- **One origin.** The browser sees the portal and the API under the same
  origin; a reverse proxy sends `/api/v1/*` (HTTP and WebSocket) to the API
  and everything else to Next.js. For development and the browser tests this
  is `web/scripts/edge.mjs` (no dependencies; it overwrites
  X-Forwarded-For, and the API runs with `trust_proxy = true`); production
  uses a TLS reverse proxy (phase 8 deployment). Consequences: no CORS, the
  session cookie stays SameSite=Strict, the CSP needs only `connect-src
  'self'`, and the passkey relying party is the portal's host.
- **Pages render on the client** and fetch through the generated client
  (`openapi-typescript` + `openapi-fetch`, `web/lib/api/`). The Next.js
  server never calls the API and holds no credentials; it only serves the
  app and sets headers. `pnpm --filter web check:api` fails when the
  generated types differ from `docs/openapi.json`, which a Rust test keeps in
  sync with the API.
- **CSRF token** from the login response / `GET /me` is kept in
  sessionStorage (it must survive a reload during the 2FA step). It is not a
  secret from same-origin scripts; the session cookie remains HttpOnly.
- **CSP** with a per-request nonce (`web/proxy.ts`): `script-src 'self'
  'nonce-…' 'strict-dynamic'`, no `unsafe-inline`/`unsafe-eval` for scripts
  in production, `frame-ancestors 'none'`, `object-src 'none'`,
  `connect-src 'self'`. `style-src` allows inline styles (charts and
  Next.js set style attributes; scripts remain locked down). HSTS and
  `upgrade-insecure-requests` only on HTTPS. Static headers
  (X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP)
  in `next.config.ts`.
- **Tenant routing** is `/t/<tenant id>/…`. The portal shows a tenant only
  if `/me` lists it; it never asks the API about other tenant ids (and the
  API would answer 404).
- **UI kit:** shadcn/ui-style components written into `web/components/ui`
  (Radix Slot, class-variance-authority, Tailwind CSS 4), Recharts for the
  live graph. Dark mode follows the system, with a manual override.
- **Supply chain:** pnpm workspace with a lockfile, `minimumReleaseAge` of
  14 days and an allowlist for install scripts; Node is installed from a
  pinned, checksummed tarball in the test image.

**Alternatives.** Server components calling the API with the user's cookie
(a second network hop and credentials on the Next.js server, for little
gain in a logged-in dashboard); a separate API origin with CORS
(SameSite/CSRF and passkey RP complications).
