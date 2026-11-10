# Running and testing

## Requirements

- Linux kernel 6.x (native XDP, bpf_link for XDP, BPF_PROG_TEST_RUN)
- clang/LLVM, libbpf headers (`libbpf-dev`), `libelf-dev`, `zlib1g-dev`, `pkg-config`
- Rust (version pinned in `rust-toolchain.toml`; rustup picks it up)
- For tests: `iproute2`, `iputils-ping`, `jq`, `python3`, `nsenter` (util-linux)
- bpffs mounted at `/sys/fs/bpf` (systemd does this; otherwise
  `mount -t bpf bpf /sys/fs/bpf`)

## Build and test

```sh
make                         # build/ebpf/xdp_main.o + target/debug/sentinelctl
make test                    # cargo fmt --check, clippy -D warnings, cargo test
sudo make test-bpf           # 64 BPF_PROG_TEST_RUN cases
sudo make test-integration   # veth/netns, native XDP, exact counters
```

`sudo make test-integration` does not build the CLI (cargo is usually not on
root's PATH), so run `make` as your normal user first.

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
sentinelctl attach --iface eth0 [--obj build/ebpf/xdp_main.o]
sentinelctl stats               # table
sentinelctl stats --json        # {"entries":[{"tenant":0,"verdict":"pass","pkts":..,"bytes":..}]}
sentinelctl stats --watch --interval 1
sentinelctl observe on          # count malformed frames but pass them
sentinelctl observe off
sentinelctl detach --iface eth0
```

Every flag has an environment equivalent (see `.env.example`):
`XS_IFACE`, `SENTINEL_BPF_OBJ`, `SENTINEL_PIN_DIR`.

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
