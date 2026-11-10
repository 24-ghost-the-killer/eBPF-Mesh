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

## Dataplane (phase 1)

### Pipeline

```
frame ─► parse ──malformed──────────────► count DROP_MALFORMED ─► XDP_DROP
           │                                                     (XDP_PASS if observe)
           ├──non-IP (ARP, LLDP…)───────► count PASS_NON_IP ────► XDP_PASS
           ├──non-first fragment────────► count FRAGMENT ───────► XDP_PASS
           └──ok────────────────────────► count PASS ───────────► XDP_PASS
```

Later phases insert, in this order: own-unicast pass, bogon filter, tenant
lookup, allowlist, blocklist, allowed services, rate limit / SYN cookies,
sampling, IPIP encapsulation.

### Parser rules

| Layer | Accepted | Malformed when |
|---|---|---|
| Ethernet | ≥ 14 bytes | shorter |
| VLAN | up to 2 tags (0x8100, 0x88A8) | a 3rd tag, truncated tag |
| IPv4 | version 4, IHL ≥ 5, options | IHL < 5, header beyond frame, `tot_len` < IHL or beyond frame |
| IPv4 fragments | first fragment parsed normally; later fragments → `FRAGMENT` | first fragment too short for its L4 header |
| IPv6 | version 6, `payload_len` within frame | truncated header, `payload_len` beyond frame |
| IPv6 ext. headers | HOP, ROUTING, DEST, AUTH, FRAGMENT; up to 4 | 5th header, header beyond frame or `payload_len` |
| TCP | `doff` ≥ 5, header inside frame and IP length | otherwise |
| UDP, ICMP, ICMPv6 | 8-byte header inside frame and IP length | otherwise |
| Other L4 (GRE, ESP…) | parsed at L3 only | – |

Trailing Ethernet padding (IP length shorter than the frame) is valid.

### Maps

| Map | Type | Key → Value | Written by |
|---|---|---|---|
| `xs_cfg` | ARRAY(1) | 0 → `{flags}` (`XS_CFG_F_OBSERVE`) | `sentinelctl observe` |
| `xs_stats` | PERCPU_HASH(65536) | `{tenant, verdict}` → `{pkts, bytes}` | XDP (`sentinelctl stats` reads) |

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
