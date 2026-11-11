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

## Dataplane (phases 1-3)

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
 │10 deliver ───────── IPIP / 6in4 to origin ───► XDP_TX (verdict kept)
 │                     too big / no PoP IP ─────► DROP_TOO_BIG / DROP_TUNNEL
```

[global] drops are suspended only by the kill switch (`XS_CFG_F_OBSERVE`).
[policy] drops and challenges happen only when the asset's policy has
`XS_P_MITIGATE`; otherwise (observe mode, the default) the verdict is counted
and the packet is still delivered. Step 9 (sampling) arrives with the agent.

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
| `xs_cfg` | ARRAY(1) | 0 → kill switch, PoP IPv4/IPv6, tunnel endpoint, next-hop MAC, uplink MTU, SYN-cookie key, verify TTL | `sentinelctl attach/config/observe/syncookie` |
| `xs_tenants`, `xs_tenants6` | LPM_TRIE | protected prefix → asset {tenant, id, origin, policy {flags, pps, burst}} | `sentinelctl asset/policy` |
| `xs_allow`, `xs_allow6` | LPM_TRIE | {32+len, tenant, src} → {expires_ns (0 = permanent), reason} | `sentinelctl allow` |
| `xs_block`, `xs_block6` | LPM_TRIE | same → {expires_ns (> 0), reason} | `sentinelctl block` |
| `xs_services` | HASH | {asset, proto, port (0 = all)} → 1 | `sentinelctl service` |
| `xs_rl` | LRU_HASH(262144) | {tenant, addr (v4-mapped; v6 /64)} → {tokens·1e9, last_ns} | XDP |
| `xs_verified` | LRU_HASH(262144) | {tenant, addr} → expires_ns | XDP (`gc` cleans) |
| `xs_stats` | PERCPU_HASH(65536) | {tenant, verdict} → {pkts, bytes} | XDP |

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

## Decisions

See [docs/adr/](adr/).
