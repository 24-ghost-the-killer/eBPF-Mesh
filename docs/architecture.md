# Architecture

## The whole system (target)

```
Browser -> Web app (Next.js) -> Control-plane API (axum)
                                   |-> PostgreSQL (customers, users, rules, audit)
                                   |-> ClickHouse (traffic, flows)
                                   |-> NATS (KV config, decisions, stats, health)
                                          |
         +-------------------+------------+------+--------------------+
         |                   |                   |                    |
      PoP Europe          PoP USA            PoP Asia          Analysis workers
   (BIRD + XDP + agent) (BIRD + XDP + agent) (BIRD + XDP + agent) (detect, sign)
         ^                   ^                   ^
         +---------- clients and botnets (anycast) ----------+
         |
         +--> clean traffic in IPIP tunnel --> customer's own server (origin)
```

- Every PoP announces the same prefix (anycast); routing splits an attack
  geographically.
- In each PoP an XDP program filters per customer and tunnels clean packets
  to the customer's origin with `XDP_TX`.
- The agent samples packets, publishes telemetry and stats over NATS and
  applies configuration and signed decisions to BPF maps.
- The packet path never waits for userspace. Every dynamic mitigation has a
  TTL enforced inside XDP.

## Dataplane (phases 1-4)

### Pipeline

```
frame
 │ 1 parse ─────────── malformed ───────────────► DROP_MALFORMED   [global]
 │                     non-IP (ARP, LLDP…) ─────► PASS_NON_IP (kernel)
 │ r return ────────── dst = tunnel endpoint ───► TX_RETURN / DROP_RETURN
 │ 2 local ─────────── dst = PoP IP, IPv6 ND ───► PASS_LOCAL (kernel)
 │ 3 bogon source ──────────────────────────────► DROP_BOGON       [global]
 │ 4 asset lookup ──── none ────────────────────► DROP_NO_TENANT   [global]
 │ 5 allowlist ─────── tenant, then global ─────► PASS_ALLOW (skips 6-8)
 │ 6 blocklist ─────── expires_ns > now ────────► DROP_BLOCK       [policy]
 │ 7 services ──────── proto+port (ICMP errors ─► DROP_SERVICE     [policy]
 │                     always pass)
 │   fragments ─────── non-first, policy drops ─► DROP_FRAGMENT    [policy]
 │ 8 token bucket ──── per source (v6: per /64) ► DROP_RATELIMIT   [policy]
 │   SYN cookies ───── unverified SYN ──────────► TX_SYN_CHALLENGE (XDP_TX)
 │                     RST with valid cookie ───► SYN_VERIFIED (consumed)
 │                     other TCP, unverified ───► DROP_UNVERIFIED  [policy]
 │ 9 sample ────────── 1 in N, any verdict ─────► xs_events ring buffer
 │10 deliver ───────── IPIP / 6in4 to origin ───► XDP_TX (verdict kept)
 │                     too big / no PoP IP ─────► DROP_TOO_BIG / DROP_TUNNEL
```

[global] drops are suspended only by the kill switch (`XS_CFG_F_OBSERVE`).
[policy] drops and challenges happen only when the asset's policy has
`XS_P_MITIGATE`; otherwise (observe mode, the default) the verdict is counted
and the packet is still delivered.

The main program parses, looks up the asset and dispatches; policy
evaluation, delivery, the return path and MSS clamping are global BPF
functions that the verifier checks independently
([ADR 0013](adr/0013-bpf-global-functions.md)).

### Tunnel delivery and return

```
client ──► router ──► PoP XDP ──IPIP(src PoP IP, dst origin)──► router ──► origin
                                                                      │ decapsulates,
                                                                      │ sees client IP
client ◄── router ◄── PoP XDP ◄──IPIP(src origin, dst tunnel EP)──────┘
                     validate origin, clamp MSS, decapsulate
```

The tunnel endpoint is an anycast address, so replies reach the PoP nearest
the origin. With DSR the origin replies directly instead. See
[ADR 0012](adr/0012-tunnel-delivery-and-return.md).

### SYN-cookie source verification

```
client                      XDP (PoP)                         origin
SYN(isn) ─────────────────► unverified → XDP_TX SYN-ACK
         ◄───────────────── (seq=h>>32, ack=cookie ≠ isn+1)
RST(seq=cookie) ──────────► valid → xs_verified[src]=now+ttl, drop
SYN(isn) (retransmit) ────► verified → tunnel ──────────────► handshake
```

cookie = SipHash-2-4(key, saddr, daddr, sport, dport, ⌊now / 2^34 ns⌋); the
current and previous slot are accepted. See
[ADR 0009](adr/0009-syncookie-source-verification.md).

### Parser rules

| Layer | Accepted | Malformed when |
|---|---|---|
| Ethernet | ≥ 14 bytes | shorter |
| VLAN | up to 2 tags (0x8100, 0x88A8) | a 3rd tag, truncated tag |
| IPv4 | version 4, IHL ≥ 5, options | IHL < 5, header beyond frame, `tot_len` < IHL or beyond frame |
| IPv4 fragments | first fragment parsed normally; later fragments carry no L4 header and go to the fragment policy (step 7) | first fragment too short for its L4 header |
| IPv6 | version 6, `payload_len` within frame | truncated header, `payload_len` beyond frame |
| IPv6 ext. headers | HOP, ROUTING, DEST, AUTH, FRAGMENT; up to 4 | 5th header, header beyond frame or `payload_len` |
| TCP | `doff` ≥ 5, header inside frame and IP length | otherwise |
| UDP, ICMP, ICMPv6 | 8-byte header inside frame and IP length | otherwise |
| Other L4 (GRE, ESP…) | parsed at L3 only | – |

Trailing Ethernet padding (IP length shorter than the frame) is valid.

### Maps

| Map | Type | Key → Value | Written by |
|---|---|---|---|
| `xs_cfg` | ARRAY(1) | 0 → kill switch, PoP IPv4/IPv6, tunnel endpoint, next-hop MAC, uplink MTU, sample rate, SYN-cookie key, verify TTL | `sentinelctl attach/config/observe/syncookie` |
| `xs_tenants`, `xs_tenants6` | LPM_TRIE | protected prefix → asset {tenant, id, origin, policy {flags, pps, burst}} | `sentinelctl asset/policy` |
| `xs_allow`, `xs_allow6` | LPM_TRIE | {32+len, tenant, src} → {expires_ns (0 = permanent), reason} | `sentinelctl allow` |
| `xs_block`, `xs_block6` | LPM_TRIE | same → {expires_ns (> 0), reason} | `sentinelctl block` |
| `xs_services` | HASH | {asset, proto, port (0 = all)} → 1 | `sentinelctl service` |
| `xs_rl` | LRU_HASH(262144) | {tenant, addr (v4-mapped; v6 /64)} → {tokens·1e9, last_ns} | XDP |
| `xs_verified` | LRU_HASH(262144) | {tenant, addr} → expires_ns | XDP (`gc` cleans) |
| `xs_stats` | PERCPU_HASH(65536) | {tenant, verdict} → {pkts, bytes} | XDP |
| `xs_events` | RINGBUF(4 MiB) | 64-byte `xs_event` per sampled packet | XDP (agent reads) |
| `xs_counters` | PERCPU_ARRAY | events lost (ring buffer full) | XDP |

All times are CLOCK_BOOTTIME ns; expiry is enforced inside XDP
([ADR 0011](adr/0011-expiry-and-fail-open.md)).

### ABI

`ebpf/include/abi.h` is the only definition of shared structs and constants.
`crates/common/src/abi.rs` mirrors it with `#[repr(C)]` and const asserts;
its tests parse `abi.h` and fail if a `#define`, a verdict value or a struct
size/alignment differs. Verdicts are append-only.

### Pinning and attachment

```
$SENTINEL_PIN_DIR (default /sys/fs/bpf/sentinel)
  xs_cfg, xs_stats        maps, shared by every attached interface
  link_xdp_<ifname>       pinned bpf_link, one per interface
```

`sentinelctl attach` loads the object (reusing pinned maps), creates an XDP
`bpf_link` with `XDP_FLAGS_DRV_MODE` (or `SKB_MODE` with `--allow-generic`) and
pins it. The program stays attached after the CLI exits and cannot be silently
replaced. `detach` detaches the link, removes its pin, and removes the map pins
once no interface uses them. See [ADR 0007](adr/0007-loader-and-attachment.md).

## PoP agent (phase 4)

```
            NATS (TLS, nkey user "pop <id>")
   KV tenants/services/rules/platform ──watch──┐      ┌──► config.ack.<pop>
                                               ▼      │──► stats.<pop>         (1 s)
 sentinel-agent ─── reconcile maps ──► xs_tenants*, xs_services, xs_allow*/block*, xs_cfg
      │                                                │──► telemetry.<pop>.<shard> (1 s, flows)
      ├─ ring buffer thread ◄── xs_events              │──► health.<pop>        (5 s)
      ├─ heartbeat file, Prometheus /metrics           └──► (decision.global: phase 7)
      └─ gc every 10 s, adaptive sample rate
```

- **Config flow:** each bucket is watched ("last value per key"). After the
  initial snapshot and after every change the agent rebuilds the maps that
  bucket owns and acknowledges the change (ADR 0015).
- **Telemetry:** sampled events are aggregated per second into flows keyed by
  (tenant, src, dst, proto, dport, verdict), scaled by the sample rate, and
  published per shard of the source /24 or /48. When events per second exceed
  the target the sampling divisor goes up; it comes back down when quiet.
- **Failure behaviour:** a crashed agent leaves XDP attached with the last
  state; time-limited entries keep expiring in XDP. A restarted agent adopts
  the attachment and resyncs. SIGTERM detaches (spec), `--keep-attached`
  doesn't (upgrades).
- **Security:** see ADR 0014.

## Control plane (phase 5)

```
browser / API client ── HTTPS ──► sentinel-api (axum)
                                    │  every request: transaction with
                                    │  app.user_id / tenant_id / key_tenant
                                    ▼
                                 PostgreSQL (RLS on every tenant table)
                                    │  same transaction: kv_outbox rows
                                    ▼
                         outbox publisher ──► NATS KV ──► agents ──► XDP maps
                                    ▲                        │
              config_acks, pops ◄───┴── config.ack.*, health.* ┘
```

- **Auth:** argon2id, server-side sessions (hashed tokens) in HttpOnly
  SameSite=Strict cookies, per-session CSRF tokens, TOTP 2FA (encrypted at
  rest), DB-backed login rate limits, scoped API keys (hashed). ADR 0016.
- **Authorisation:** the role comes from the membership row (or the API
  key), checked by every handler; PostgreSQL RLS repeats the check and
  requires membership, never trusting the tenant id from the URL.
- **Configuration flow:** PostgreSQL first, then KV through the outbox;
  "active on X of Y PoPs" compares the asset's `config_version` with the
  versions each agent acknowledged.
- **Endpoints and deviations:** ADR 0017; the OpenAPI document is the
  contract for the web app.

## Portal (phase 6)

```
browser ──► reverse proxy (one origin) ──► Next.js (pages, CSP nonce, headers)
                     │
                     └── /api/v1/* (HTTP + WebSocket) ──► sentinel-api
                                                           │  stats.> (latest per PoP)
                                                           │  probe.<pop> request/reply
                                                           ▼
                                                         NATS ◄──► agents
```

- Pages render in the browser and call the API through a client generated
  from the OpenAPI document; the Next.js server holds no credentials
  (ADR 0018).
- **Live view:** the API subscribes to `stats.>` once and keeps the latest
  message per PoP; each `/tenants/{id}/live` WebSocket gets one frame per
  second built only from its tenant's rows (in / filtered / clean / return
  rates, per PoP and per verdict). The Origin header must match the portal;
  the session is re-checked every 30 s.
- **Passkeys** are a second factor next to TOTP (ADR 0019).
- **Tunnel test:** every live PoP pings the protected IP through the real
  tunnel and return path (ADR 0020).

## Decisions

See [docs/adr/](adr/).
