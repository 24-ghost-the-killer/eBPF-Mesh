# 0016 API: sessions, CSRF, Row Level Security, outbox

**Status:** Accepted (phase 5)

**Sessions.** Login returns a 256-bit random token in an `HttpOnly; Secure;
SameSite=Strict` cookie; PostgreSQL stores only its SHA-256. Sessions expire
after 12 h absolute or 1 h idle (configurable) and are revocable: logout,
enabling 2FA (other sessions) and password reset (all sessions) delete them.
No JWTs, nothing in localStorage.

**CSRF.** Each session has its own random CSRF token, returned by login and
`GET /me`. Every state-changing request with a session must echo it in
`X-CSRF-Token` (constant-time comparison). API-key requests are exempt
(no ambient credential).

**2FA.** TOTP (RFC 6238, ±1 step); a code is accepted once (last step
stored). Secrets are AES-256-GCM encrypted at rest with a key from the
environment. A session of a user with 2FA can only verify the code or log
out until it does. Enabling mitigate mode, creating API keys and every
platform-admin endpoint require 2FA. Passkeys follow in phase 6.

**Rate limits and enumeration.** Failed logins and failed 2FA codes are
recorded in PostgreSQL (works with several API instances); 5 per account or
30 per IP within 15 minutes give 429. Unknown accounts are checked against
a dummy argon2id hash (same timing). Signup and password reset always answer
202; an existing address gets a notice mail instead.

**Row Level Security.** The API runs as `sentinel_api` (not the owner, no
BYPASSRLS). Each request is a transaction that sets `app.user_id`,
`app.tenant_id`, `app.key_tenant` and `app.is_admin`. Policies require the
row's tenant to equal `app.tenant_id` **and** `app_tenant_ok()`: the user is
a member of that tenant, or a database-verified API key belongs to it (or a
platform admin). The tenant id alone, which comes from the URL, is never
enough: tested by removing the application's role check entirely, which
still leaks nothing. Narrow `SECURITY DEFINER` functions cover the two
cross-tenant needs: looking up an API key by hash and listing used
protected prefixes for allocation.

**Outbox.** Every configuration change writes its KV documents to
`kv_outbox` in the same transaction; a publisher writes them to NATS KV in
order and deletes them after NATS confirmed. NATS outages delay but never
lose configuration. Agents' `config.ack.*` and `health.*` are stored in
`config_acks` and `pops`, which drive "active on X of Y PoPs".
