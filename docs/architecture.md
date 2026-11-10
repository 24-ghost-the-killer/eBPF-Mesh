# Architecture

eBPF Mesh is a lab-scale anycast DDoS-scrubbing platform. This page describes
the target design and, in detail, what exists today (Phase 0).

## Target design (all phases)

```
              internet / lab "regions" (AS 65001-65003)
                 |               |               |
          anycast prefix announced by BIRD 2 from every PoP (AS 65010)
                 |               |               |
            +---------+     +---------+     +---------+
            |  PoP A  |     |  PoP B  |     |  PoP C  |
            |  NIC    |     |  NIC    |     |  NIC    |
            |  XDP  --+-- filter per tenant, SYN cookies, rate limits
            |   |     |     |         |     |         |
            |   +-- IPIP encap + XDP_TX --> customer origin (decaps, VIP on lo)
            |   |     |     |         |     |         |
            | agent --+-- samples -> NATS (partitioned by src /24, /48) --> workers
            |   ^     |     |         |     |         |       |
            |   +-----+-- signed decisions (Ed25519, TTL) <-----+
            +---------+     +---------+     +---------+
```

| Phase | Adds |
|---|---|
| 0 | Scaffolding, bounded parser, per-CPU counters, `meshctl attach/detach/stats` (**this phase**) |
| 1 | Bogon filter, blocklist (LPM trie + TTL), per-source token bucket, SYN cookies |
| 2 | Multi-tenant: dst-prefix LPM trie -> tenant {id, origin, flags, pps}, `meshctl tenant` |
| 3 | IPIP encapsulation in XDP + XDP_TX to the customer origin |
| 4 | containerlab anycast lab, BIRD health check |
| 5 | Ring-buffer sampling, flows/features, NATS partitioning, `mesh-worker` detector |
| 6 | Ed25519-signed decisions shared between PoPs; local allowlist always wins |
| 7 | Tenant dashboard / API |

Invariants that hold in every phase:

- **The packet path never waits for userspace.** XDP only reads maps.
- **Every mitigation has a TTL.** If userspace dies, mitigations expire and
  the dataplane falls back to passing traffic, never to dropping everything.
- **Observe-only by default.** An all-zero configuration passes everything;
  dropping is opt-in (per tenant from Phase 2).
- **Lab only.** Documentation/private address ranges and private ASNs.

## Repository layout

```
ebpf/src/            XDP program and headers (C, GPL-2.0-only OR BSD-2-Clause)
  abi.h              shared ABI: counter slots, parse codes, struct sizes
  parsers.h          bounded Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP parser
  account.h          parse result -> counter slots
  maps.h             BPF maps
  em_xdp.c           entry point
userspace/
  common/            em-common: ABI mirror (abi.rs), pin layout (pin.rs)
  ctl/               meshctl
  agent/             mesh-agent (Phase 0: config stub)
  worker/            mesh-worker (Phase 0: config stub)
tests/
  common/            packet builder + shared corpus (cases.h)
  bpf/               parser_host.c (host), test_xdp.c (kernel)
  integration/       veth.sh + send_frames.py
configs/             example configs (no real IPs, no secrets)
lab/                 Phase 4 lab (placeholder)
scripts/             dev VM setup, dev container
docs/                this documentation
```

## Phase 0 dataplane

### Pipeline (per frame)

```
em_xdp_main(ctx)
  1. st = lookup(em_stats, 0)            one PERCPU_ARRAY lookup
  2. count RX
  3. rc = em_parse(ctx, &pkt)            global function, verified once
  4. em_account_parse(st, &pkt, rc)      classification counters
  5. count VERDICT_PASS; return XDP_PASS
```

No helper other than the map lookup is called. Later phases insert stages
between 4 and 5: filtering (1), tenant lookup (2), encapsulation (3).

### Parser

`parsers.h` is pure C over `(data, data_end)`, compiled both for BPF and for
the host tests. Rules:

- every packet read is preceded by a bounds check on the exact pointer;
- every length field from the packet (IHL, TCP data offset, IPv4 total
  length, IPv6 payload length, extension header length, UDP length) is masked,
  checked against its legal minimum and against `data_end` before use;
- loops have compile-time trip counts: at most 2 VLAN tags (802.1Q, 802.1ad,
  0x9100) and at most 6 IPv6 extension headers;
- the IPv6 extension chain is walked with a masked scalar offset rather than
  an advancing pointer, so each unrolled iteration starts from the same
  verifier state and path pruning works.

Output is a 64-byte `struct em_pkt` on the stack (addresses, ports, protocol,
TCP flags, TTL, fragment state, VLAN IDs, anomaly bits) that later phases
filter on.

Parse results (`enum em_parse_rc` in `abi.h`):

| Class | Codes | Meaning |
|---|---|---|
| OK | `OK`, `NOT_IP` | well formed |
| UNSUP | `UNSUP_VLAN_DEPTH`, `UNSUP_IPV6_EXT_DEPTH` | legal, beyond what the fast path parses |
| ERR | `ERR_*` (16 codes) | malformed per the RFCs |

Phase 0 passes all three classes; Phase 1 can drop on them, per tenant.

### Verification boundary

`em_parse()` is a global (non-static, noinline) BPF function. The verifier
checks it once, independently of its caller, and the caller sees `rc` and
`pkt` as unknown values. Without the boundary every parser outcome would be
carried as a separate verifier state through all later stages. Measured on
kernel 7.0 (arm64): 778 instructions, 25,031 verifier steps (limit 1,000,000),
64 bytes of stack.

### Counters

`em_stats` is a `PERCPU_ARRAY` with one element, `struct em_stats`, holding
128 slots of `{packets, bytes}` (2 KiB per CPU). One lookup per packet, no
atomics; userspace sums the CPUs.

| Slots | Counters |
|---|---|
| 0-4 | `rx`, `verdict_pass/drop/tx/redirect` |
| 8-9 | `l2_vlan1`, `l2_vlan2` |
| 16-19 | `l3_ipv4/ipv6/arp/other` |
| 24-28 | `l4_tcp/udp/icmp/icmpv6/other` (rc == OK) |
| 32-34 | `frag_first`, `frag_later`, `ipv6_ext` (rc == OK) |
| 40-44 | `tcp_syn/synack/ack/fin/rst` (TCP header parsed) |
| 48-53 | `anom_ipv4_options/tcp_bad_flags/udp_len_mismatch/land/ttl_zero/port_zero` (rc == OK) |
| 64-87 | `parse_<code>`: exactly one per frame |

Invariants checked by the tests: `sum(parse_*) == rx` and
`sum(verdict_*) == rx`. Unlisted slots are reserved for later phases; slot
numbers are never reused for a different meaning.

### ABI

`abi.h` is the single source of truth. `userspace/common/src/abi.rs` mirrors
it with `const` size assertions; `_Static_assert`s in `abi.h` pin the same
sizes on the C side, and a Rust unit test parses `abi.h` and fails on any drift
in slot numbers, parse codes, sizes or `EM_ABI_VERSION`. `test_xdp` also checks
the map's value size in the compiled object.

### Attachment and pins

`meshctl attach` loads the object with libbpf-rs, pins every map under
`<pin_root>/<iface>/`, attaches through the netlink XDP API and pins the
program as `<pin_root>/<iface>/em_xdp_main`:

- the attachment belongs to the interface, so the dataplane keeps running when
  `meshctl` (or later the agent) exits or crashes;
- the mode is explicit (`--mode native|generic`); a NIC without native XDP is
  an error, never a silent fallback;
- a fresh attach uses `XDP_FLAGS_UPDATE_IF_NOEXIST` and never clobbers another
  program;
- `--replace` and `detach` use `XDP_FLAGS_REPLACE` with the pinned program as
  the expected old program. They are compare-and-swap operations, and both refuse
  a program that `meshctl` did not attach;
- maps are reused across `--replace`, so counters survive upgrades; the
  program pin is swapped by pin-then-rename, so it is never missing.
