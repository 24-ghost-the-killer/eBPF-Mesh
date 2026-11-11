# 0004 BPF policy is per protected prefix (asset), not per tenant

**Status:** Accepted (implemented in phase 3)

**Context.** Spec §5.2/§5.3 key origin IP, flags and services by *tenant*
(`xs_tenant`, `xs_services {tenant, proto, port}`), while the data model
(§12.1) stores origin IP, mode and policy per *asset* (protected IP). A tenant
with two servers (different origins, different open ports, one in observe
and one in mitigate) cannot be expressed with per-tenant maps.

**Decision.** The `xs_tenants` LPM value describes one asset:
`{tenant_id, asset_id, origin_ip, flags, pps_per_src}`. `xs_services` is keyed
by `{asset_id, proto, port}`. Statistics and allow/block rules stay keyed by
tenant (rules are owned by the tenant; tenant 0 = global), so `xs_stats`
keeps `{tenant, verdict}`.

**Consequences.** Maps match the database model one-to-one; a few bytes more
per LPM entry.
