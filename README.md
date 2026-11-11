# Sentinel-Edge

An anycast DDoS-protection platform: every Point of Presence (PoP) announces
the same prefix over BGP, an XDP program on the PoP's NIC filters traffic per
customer, and clean packets are tunnelled (IPIP) to the customer's own server.
A Rust agent, analysis workers and a control-plane API coordinate over NATS; a
Next.js portal sits in front of the API.

**Lab only.** Everything uses documentation/private address ranges and private
ASNs. Nothing here is meant to touch the real internet yet.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: repo, CI, XDP parser + per-CPU counters, `sentinelctl` attach/detach/stats | done |
| 2 | Filtering: bogons, allow/blocklists, services, rate limit, SYN cookies, observe/mitigate | **done** |
| 3 | Tenants and IPIP tunnel delivery | next |
| 4 | PoP agent and NATS | |
| 5 | Control-plane API and PostgreSQL | |
| 6 | Portal v1 | |
| 7 | Analysis workers and signed decisions | |
| 8 | Anycast lab (containerlab + BIRD) | |
| 9 | Public website | |

## What exists today

- **XDP program** (`ebpf/`), in pipeline order:
  1. parse Ethernet, 2 VLAN tags, IPv4/IPv6 (extension headers, fragments),
     TCP/UDP/ICMP; malformed → drop
  2. traffic to the PoP's own IP and IPv6 neighbour discovery → pass
  3. bogon sources (RFC1918, loopback, multicast, ...) → drop
  4. (tenants arrive in phase 3; until then one default policy)
  5. allowlist (tenant, then global) → pass, skipping 6-8
  6. blocklist with expiry enforced inside XDP → drop
  7. allowed services (proto + port), fragment policy → drop the rest
  8. per-source token bucket (IPv6 per /64), then **SYN-cookie source
     verification**: unverified SYNs are answered from XDP with a challenge
     SYN-ACK; the client's RST proves the address is real
     ([ADR 0009](docs/adr/0009-syncookie-source-verification.md))

  New policies start in **observe** mode: every verdict is counted, nothing is
  dropped. A global kill switch suspends all drops.
- **`sentinelctl`**: attach/detach (native XDP, pinned `bpf_link`), stats,
  policy, services, allow/block rules with TTL, PoP config, SYN-cookie key
  rotation, gc. `--json` on every read command.
- **`sentinel-gen`**: lab-only SYN/ACK/UDP flood generator with spoofed
  sources; refuses anything outside the lab ranges.
- **Shared ABI** (`ebpf/include/abi.h` ⇄ `crates/common/src/abi.rs`), checked
  for drift by a Rust test that parses the header.
- **Tests**: 188 `BPF_PROG_TEST_RUN` checks (verdicts, exact counters, exact
  SYN-ACK bytes for IPv4/IPv6/VLAN), 3 veth/netns suites with real traffic,
  39 Rust unit tests, CI.

The phase 2 acceptance test (`tests/integration/synflood.sh`): 80 000 spoofed
SYNs at 20 000 pps reach the PoP; the server's TCP stack sees 7 segments (all
from the real client), and a concurrent `curl` gets the page in ~15 ms.

## Quick start

On Linux (kernel 6.x, root for the BPF parts):

```sh
sudo apt-get install clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config \
     iproute2 iputils-ping jq curl python3      # plus a Rust toolchain (rustup)
make                          # XDP object + Rust workspace
make test                     # fmt, clippy, unit tests
sudo make test-bpf            # BPF_PROG_TEST_RUN tests
sudo make test-integration    # veth/netns end-to-end tests

sudo target/debug/sentinelctl attach --iface eth0 --pop-ip4 10.10.1.1
sudo target/debug/sentinelctl service add --proto tcp --port 443
sudo target/debug/sentinelctl policy set --enforce-services on --syncookies on --pps-per-src 1000
sudo target/debug/sentinelctl stats --watch      # observe first ...
sudo target/debug/sentinelctl policy set --mitigate on   # ... then enforce
```

On macOS (Docker Desktop): `make docker-test` runs every suite inside a
privileged Linux container; `make docker-shell` opens a shell there.

See [docs/running.md](docs/running.md) for the full runbook.

## Repository layout

```
ebpf/include/abi.h        shared kernel/userspace structs and constants
ebpf/src/                 XDP program: parse.h, policy.h, syncookie.h, cookie.h, maps.h
crates/common             ABI mirror, pin layout, prefixes, lab ranges, stats
crates/ctl                sentinelctl (operator CLI)
crates/gen                sentinel-gen (lab traffic generator)
crates/{agent,worker,api} placeholders for phases 4, 7, 5
tests/bpf                 BPF_PROG_TEST_RUN harness, parser and policy suites
tests/integration         veth/netns suites (counts, live policy, SYN flood)
deploy/docker             development/test image
docs/                     architecture, runbook, ADRs
```

## Known limitations (after phase 2)

- One default policy for all destinations; per-tenant/per-asset policies and
  IPIP delivery arrive in phase 3 ([ADR 0004](docs/adr/0004-per-asset-bpf-policy.md)).
- SYN cookies add one round trip to the first connection of each source per
  TTL; only SYNs without IPv4 options / IPv6 extension headers are challenged.
- In observe mode with SYN cookies on, all non-SYN TCP counts as
  `drop_unverified` (nothing gets verified without challenges).
- An expired longer prefix shadows an active shorter one until `gc` runs
  ([ADR 0011](docs/adr/0011-expiry-and-fail-open.md)); the agent will run it
  continuously from phase 4.
- VLAN tags are parsed only when in the packet (disable rx-vlan offload,
  [ADR 0003](docs/adr/0003-vlan-offload.md)).

## License

`ebpf/` and the C tests: GPL-2.0-only OR BSD-2-Clause. Everything else:
MIT OR Apache-2.0. See [LICENSE](LICENSE).
