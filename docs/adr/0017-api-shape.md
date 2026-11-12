# 0017 API shape: per-asset policy and onboarding details

**Status:** Accepted (phase 5; approved by the project owner)

- **Policy per protected IP:** `GET/PUT /tenants/{id}/assets/{aid}/policy`
  instead of the spec's `/tenants/{id}/policy`. The spec's own `policies`
  table is keyed by `asset_id`, and the dataplane is per asset (ADR 0004).
  The policy body includes the allowed services.
- **Signup creates a tenant** (named in the request) with the user as owner.
- **Members** are added by the email of an existing, verified user with a
  role; invitations for new users come with the portal.
- **Protected IPs** are /32s allocated from `[anycast] prefix4` in the API
  config, skipping network, broadcast, the tunnel endpoint and
  `reserved4`, under an advisory lock.
- **API keys** have scopes `read` (viewer) and `write` (admin); a key can
  never act as owner and cannot create keys.
- **Tunnel script** endpoint takes `return=tunnel|dsr` and an optional
  existing `device`.
- **Errors** are always `{"error": "code", "message": "text"}`; resources of
  other tenants answer 404, never 403.
