# 0015 KV schema, versioning and agent ownership of maps

**Status:** Accepted (phase 4)

**Context.** Spec §7 lists KV buckets `tenants`, `rules`, `services` with
"one key per tenant". Policy is per protected prefix (ADR 0004), so one key
per tenant would force rewriting every asset of a large tenant for any
change. The spec also wants versioned acknowledgements.

**Decision.**

| Bucket | Key | Document (JSON, `"v": 1`, `"version": n`) |
|---|---|---|
| `tenants` | `asset.<id>` | `asset, tenant, prefix, origin, policy{mode, syncookies, enforce_services, fragments, pps_per_src, burst}` |
| `services` | `asset.<id>` | `services: [{proto, port?}]` |
| `rules` | `tenant.<id>` (0 = global) | `allow`, `block`: `[{prefix, expires_at (Unix ms) or null, reason}]` |
| `platform` | `global` | `observe` (kill switch) |

Documents are strict (unknown fields rejected). `version` is the API's
`config_version`; every applied or rejected change is acknowledged on
`config.ack.<pop>` with key, KV revision, version, ok and error.

*Ownership.* While the agent runs it owns the maps those buckets describe:
after its initial snapshot and after every change it reconciles the whole
bucket's maps to KV (entries KV does not describe are removed). Rebuilding
the bucket every time makes ordering, prefix changes and restarts correct by
construction. A rejected document keeps the entries it would have replaced.
PoP-local settings (PoP IPs, tunnel endpoint, next hop, MTU, sample rate)
come from the agent's config file, never from KV. `sentinelctl` warns when
it changes agent-owned maps while the heartbeat is fresh.

*Telemetry.* `telemetry.<pop>.<shard>` carries one message per shard per
second: `{"type":"flows", ..., "flows":[<spec flow records>]}`; shard =
FNV-1a 64 over the source /24 or /48, modulo the shard count.

**Consequences.** One asset change is one KV write. Expiry stays absolute
(Unix ms) in KV and is converted to the kernel boot clock on each PoP.
