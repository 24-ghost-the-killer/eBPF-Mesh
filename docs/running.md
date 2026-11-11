# Running and testing

## Requirements

- Linux kernel 6.x (native XDP, bpf_link for XDP, BPF_PROG_TEST_RUN)
- clang/LLVM, libbpf headers (`libbpf-dev`), `libelf-dev`, `zlib1g-dev`, `pkg-config`
- Rust (version pinned in `rust-toolchain.toml`; rustup picks it up)
- For tests: `iproute2` (with libbpf support for `ip link ... xdp obj`),
  `iputils-ping`, `jq`, `curl`, `python3`, `nsenter` (util-linux)
- bpffs mounted at `/sys/fs/bpf` (systemd does this; otherwise
  `mount -t bpf bpf /sys/fs/bpf`)

## Build and test

```sh
make                         # build/ebpf/xdp_main.o + target/debug/sentinelctl
make test                    # cargo fmt --check, clippy -D warnings, cargo test
sudo make test-bpf           # 188 BPF_PROG_TEST_RUN checks
sudo make test-integration   # veth_counts, policy_live, synflood
```

`sudo make test-integration` does not build the Rust binaries (cargo is
usually not on root's PATH), so run `make` as your normal user first.

| Integration suite | Proves |
|---|---|
| `veth_counts.sh` | native attach, exact per-verdict counters, generic refused, clean detach |
| `policy_live.sh` | rate limit, block/allow with TTL and gc, observe vs mitigate, kill switch, services, PoP traffic bypass |
| `synflood.sh` | phase 2 acceptance: a spoofed SYN flood never reaches the server while `curl` succeeds; control run in observe mode |

### On macOS

```sh
open -a Docker               # Docker Desktop must be running
make docker-test             # all suites in a privileged Linux container
make docker-shell            # interactive shell, repo mounted at /src
```

Cargo's registry and target directory live in Docker volumes
(`sentinel-cargo`, `sentinel-target`) so Linux artifacts never mix with the
Mac's `target/`.

## Operating sentinelctl

```sh
# attach (PoP addresses also via XS_POP_IP4 / XS_POP_IP6)
sentinelctl attach --iface eth0 --pop-ip4 10.10.1.1 --pop-ip6 2001:db8:100::1
sentinelctl detach --iface eth0

# what is happening
sentinelctl stats [--watch --interval 1]
sentinelctl --json stats        # {"entries":[{"tenant":0,"verdict":"pass","pkts":..,"bytes":..}]}

# the default policy (phase 2: applies to all protected traffic)
sentinelctl policy show
sentinelctl service add --proto tcp --port 443      # omit --port: whole protocol
sentinelctl policy set --enforce-services on --syncookies on \
    --pps-per-src 1000 --burst 2000 --fragments drop
sentinelctl policy set --mitigate on                # default is observe

# rules (tenant 0 = global; IPv4 or IPv6; /0 is refused)
sentinelctl block add 203.0.113.0/24 --ttl 10m      # blocks always expire
sentinelctl allow add 192.0.2.10                    # permanent unless --ttl
sentinelctl block list | allow list | block del 203.0.113.0/24
sentinelctl gc                                      # remove expired entries

# PoP-wide
sentinelctl config show | config set --verify-ttl 5m
sentinelctl syncookie rotate
sentinelctl observe on          # KILL SWITCH: count everything, drop nothing
sentinelctl observe off
```

Every flag has an environment equivalent where it makes sense (see
`.env.example`): `XS_IFACE`, `SENTINEL_BPF_OBJ`, `SENTINEL_PIN_DIR`,
`XS_POP_IP4`, `XS_POP_IP6`.

**Rolling out a policy.** Configure services and limits in observe mode, watch
`sentinelctl stats` until the `drop_*` counters only show traffic you really
want dropped, then `policy set --mitigate on`. With SYN cookies on, observe
mode counts all non-SYN TCP as `drop_unverified` (nothing is verified without
challenges), so judge those counters only after switching on.

## sentinel-gen (lab traffic generator)

```sh
sentinel-gen syn --dst 198.51.100.10 --dport 80 --src 203.0.113.128/25 --duration 5s --pps 20000
sentinel-gen udp --dst 198.51.100.10 --dport 53 --src 203.0.113.50 --count 3000
sentinel-gen ack --dst 2001:db8:100::10 --src 2001:db8:100:ff::/64 --count 1000
```

Each packet uses a random source from `--src`. Destination and sources must be
inside the lab ranges (spec §11.1); `--allow-non-lab-destination` disables the
check and prints a warning. Needs root (raw sockets).

### Generic mode

`--mode generic` is refused unless `--allow-generic` is also given. Generic
XDP runs after the kernel allocates an skb and is far too slow for a PoP; use
it only for tests on drivers without native XDP.

### Network namespaces

`ifindex` lookup and the XDP link are relative to the caller's network
namespace, so run `sentinelctl` inside the namespace that owns the interface.
Use `nsenter --net=/run/netns/<ns> sentinelctl ...`, **not**
`ip netns exec <ns> ...`: the latter remounts `/sys` in a private mount
namespace, which hides bpffs at `/sys/fs/bpf`, and attach fails with
"creating /sys/fs/bpf/sentinel: No such file or directory".

### VLANs on physical NICs

The parser handles in-band VLAN tags. Many NICs strip the outer tag before
XDP sees it (rx-vlan offload). On a PoP with tagged uplinks, disable it:
`ethtool -K <iface> rxvlan off`. See
[ADR 0003](adr/0003-vlan-offload.md).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `driver does not support native XDP` | NIC driver lacks XDP; pick another NIC (generic only for tests) |
| `another XDP program is already attached` | `ip link show dev <iface>`; remove the other program first |
| `already attached to <iface>` | a pinned link exists; `sentinelctl detach --iface <iface>` |
| `is not on bpffs` | `mount -t bpf bpf /sys/fs/bpf` |
| `loading ... incompatible build` | pinned maps from an older ABI; detach every interface, then attach again |
| `XDP program is not attached` (stats) | nothing attached with this `SENTINEL_PIN_DIR` |
| clients hang ~1 s on first connect | SYN cookies on and the client never answers the challenge with RST (some middleboxes drop it); allowlist the client network |
| `syncookie key MISSING` in `config show` | maps were created by an old build; detach and attach again (SYNs pass meanwhile) |
