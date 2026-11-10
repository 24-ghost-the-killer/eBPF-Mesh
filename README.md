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
| 1 | Foundation: repo, CI, XDP parser + per-CPU counters, `sentinelctl` attach/detach/stats | **done** |
| 2 | Filtering: bogons, allow/blocklists, services, rate limit, SYN cookies, observe/mitigate | next |
| 3 | Tenants and IPIP tunnel delivery | |
| 4 | PoP agent and NATS | |
| 5 | Control-plane API and PostgreSQL | |
| 6 | Portal v1 | |
| 7 | Analysis workers and signed decisions | |
| 8 | Anycast lab (containerlab + BIRD) | |
| 9 | Public website | |

## What exists today (phase 1)

- **XDP program** (`ebpf/`): parses Ethernet, up to 2 VLAN tags (802.1Q /
  802.1ad), IPv4 (options, fragments), IPv6 (up to 4 extension headers,
  fragments), TCP/UDP/ICMP/ICMPv6. Malformed frames are dropped; everything
  else is passed. Every verdict is counted per `(tenant, verdict)` in a per-CPU
  hash map. A global *observe* flag counts drops without dropping.
- **`sentinelctl`** (`crates/ctl`): attaches the program in native mode
  (generic only with `--allow-generic`) via a pinned `bpf_link`, detaches it,
  shows counters (`--json`, `--watch`) and toggles observe mode.
- **Shared ABI** (`ebpf/include/abi.h` ⇄ `crates/common/src/abi.rs`): sizes and
  alignment asserted on both sides; a Rust test parses `abi.h` and fails on any
  drift in constants, verdicts or struct layout.
- **Tests**: 64 `BPF_PROG_TEST_RUN` cases (verdict + exact counter deltas), a
  veth/netns test with native XDP and exact packet counts, Rust unit tests, CI.

## Quick start

On Linux (kernel 6.x, root for the BPF parts):

```sh
sudo apt-get install clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config \
     iproute2 iputils-ping jq python3          # plus a Rust toolchain (rustup)
make                          # XDP object + Rust workspace
make test                     # fmt, clippy, unit tests
sudo make test-bpf            # BPF_PROG_TEST_RUN parser tests
sudo make test-integration    # veth/netns end-to-end test

sudo target/debug/sentinelctl attach --iface eth0
sudo target/debug/sentinelctl stats --watch
sudo target/debug/sentinelctl detach --iface eth0
```

On macOS (Docker Desktop): `make docker-test` runs every suite above inside a
privileged Linux container; `make docker-shell` opens a shell there. `make test`
also works natively on the Mac (the Linux-only CLI paths are stubbed).

See [docs/running.md](docs/running.md) for the full runbook.

## Repository layout

```
ebpf/include/abi.h        shared kernel/userspace structs and constants
ebpf/src/                 XDP program (xdp_main.c, parse.h, maps.h)
crates/common             ABI mirror, pin layout, stats aggregation
crates/ctl                sentinelctl (operator CLI)
crates/{agent,worker,api} placeholders for phases 4, 7, 5
tests/bpf                 BPF_PROG_TEST_RUN harness and cases
tests/common              frame builder shared by C tests
tests/integration         veth/netns tests and lab-only frame sender
deploy/docker             development/test image
docs/                     architecture, runbook, ADRs
```

## Known limitations (phase 1)

- No filtering yet: every well-formed packet is passed. Tenant is always 0.
- VLAN tags are parsed only when they are in the packet. Most physical NICs
  strip them before XDP unless rx-vlan offload is disabled
  ([ADR 0003](docs/adr/0003-vlan-offload.md)).
- Non-first fragments are passed and counted; fragment policy arrives in
  phase 2 ([ADR 0002](docs/adr/0002-non-ip-and-fragments.md)).
- `sentinelctl` must run in the target network namespace with bpffs visible:
  use `nsenter --net=...`, not `ip netns exec` (see the runbook).

## License

`ebpf/` and the C tests: GPL-2.0-only OR BSD-2-Clause. Everything else:
MIT OR Apache-2.0. See [LICENSE](LICENSE).
