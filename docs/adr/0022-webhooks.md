# 0022 Attack notifications (webhooks)

**Status:** Accepted (phase 7)

**Decision.**
- Kinds: `discord`, `slack`, `http`, `email`; admin+ manages them
  (`/tenants/{id}/webhooks`, with a test endpoint). Events:
  `attack.started`, `attack.ended` (and `test`).
- `http` webhooks get a secret (shown once, stored encrypted) and are signed:
  `X-Sentinel-Timestamp: <unix s>` and `X-Sentinel-Signature:
  sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`. The body is JSON
  with the event, tenant, attack summary and a portal link.
- **SSRF protection:** https only, no credentials in URLs, no redirects;
  the host must resolve only to public addresses and the request connects
  to exactly the address that was checked (no second lookup). Discord and
  Slack targets must be those services' webhook hosts. Labs may set
  `[webhooks] allow_http` and `allow_private_targets`.
- Delivery runs in the background with 3 attempts (0, 1, 3 s), a 5 s
  timeout, and records the last status on the webhook. At most 10 webhooks
  per tenant.
