# Building, testing and running

## Where things run

| Target | macOS | Linux user | Linux root | Docker (`make docker-test`) |
|---|---|---|---|---|
| `make` (Rust workspace) | yes | yes | - | yes |
| `make` (XDP object, test binaries) | - | yes | - | yes |
| `make test` (host dataplane tests + `cargo test`) | yes | yes | - | yes |
| `make lint` | yes | yes | - | yes |
| `sudo make test-bpf` | - | - | yes | yes |
| `sudo make test-integration` | - | - | yes | yes |

Build output goes to `build/<os>-<arch>/` and `target/<os>-<arch>/`, so a
macOS checkout mounted into a Linux container never mixes artefacts.

## Requirements (Linux)

- Kernel 6.1+ with BTF (Debian 12+, Ubuntu 22.04+).
- clang/llvm 16+, libbpf-dev 1.0+, libelf-dev, zlib1g-dev, pkg-config,
  linux-libc-dev, make, gcc.
- iproute2, ping, python3 (integration test).
- Rust toolchain pinned in `rust-toolchain.toml` (rustup installs it).

`scripts/setup-dev-vm.sh` installs all of this on a Debian/Ubuntu VM.

## macOS

```sh
make test         # host dataplane tests (ASan/UBSan) + cargo test
make lint
make docker-test  # everything, incl. verifier and veth tests, in a privileged
                  # Linux container (needs Docker Desktop running)
```

Docker Desktop's Linux VM provides a real kernel (verified with
7.0.14-linuxkit, arm64): the verifier, `BPF_PROG_TEST_RUN` and native XDP on
veth all work there. `make docker-shell` opens a shell in the same container.

## Linux VM (e.g. Proxmox)

One VM is enough for every phase up to and including the Phase 4 lab
(containerlab runs all nodes as containers inside it). 2 vCPU / 4 GB is
plenty for Phases 0-3; plan 4 vCPU / 8 GB for the lab.

```sh
git clone <repo> && cd eBPF-Mesh
scripts/setup-dev-vm.sh        # once
make                           # as your user: XDP object, Rust, test binaries
make test                      # unprivileged
sudo make test-bpf             # verifier + BPF_PROG_TEST_RUN corpus
sudo make test-integration     # veth/netns end-to-end
```

The sudo targets only depend on built files, so root never runs cargo; run
`make` as your user first.

## CI

`.github/workflows/ci.yml` runs `make lint test` on Ubuntu and macOS, and
`make all` + `sudo make test-bpf` + `sudo make test-integration` on an Ubuntu
24.04 runner (real 6.x kernel).

## Using meshctl

```sh
# attach in native (driver) mode; maps and program pinned per interface
sudo meshctl attach -i eth1 --obj build/linux-x86_64/em_xdp.bpf.o

# NIC without native XDP (or a test): generic mode, explicitly
sudo meshctl attach -i eth1 --obj ... --mode generic

# upgrade the program atomically, keeping counters
sudo meshctl attach -i eth1 --obj ... --replace

# counters: table, JSON, or rates every second
sudo meshctl stats -i eth1
sudo meshctl stats -i eth1 --all
sudo meshctl stats -i eth1 --json
sudo meshctl stats -i eth1 --watch 1 --count 10

# detach and remove pins (--keep-maps keeps the counters)
sudo meshctl detach -i eth1
```

Global flags: `--pin-root` (default `/sys/fs/bpf/ebpf-mesh`), `-v` (libbpf
debug output, including the verifier log when a load fails).

`meshctl` refuses to:

- attach over an existing program without `--replace`;
- replace or detach a program it did not attach (for example one loaded with `ip link`);
- switch native <-> generic with `--replace` (detach first).

## Agent and worker (Phase 0 stubs)

```sh
mesh-agent  --config configs/agent.example.toml
mesh-worker --config configs/worker.example.toml
```

Both validate their TOML (unknown fields are errors), print what they would
manage, and exit. See `configs/*.example.toml` for every option.

## Test suites

| Suite | What it proves |
|---|---|
| `tests/bpf/parser_host.c` | 73 corpus frames: parse result, every parsed field, and that **exactly** the expected counter slots move (by 1 packet and the frame length). Truncation fuzz over every prefix of every frame, 200,000 bit-flip mutations; ASan/UBSan with a `NET_IP_ALIGN` buffer layout. |
| `tests/bpf/test_xdp.c` | The real object through the real verifier; every corpus frame via `BPF_PROG_TEST_RUN`: `XDP_PASS`, output bytes identical to input, exact per-slot counter deltas; `sum(parse) == sum(verdicts) == rx`. |
| `cargo test` | ABI drift against `abi.h`, per-CPU summing, wrapping deltas, pin layout and interface name validation, CLI parsing, config validation, output rendering. |
| `tests/integration/veth.sh` | 27 checks on a veth pair + netns: native and generic attach (verified from the kernel's view), ping through XDP, crafted malformed frames counted exactly, invariants, refusal of double attach and cross-mode replace, atomic replace keeps counters, clean detach, refusal to replace/detach a foreign program. |

## Known limitations (Phase 0)

- **Observe-only.** Nothing is dropped yet; that is Phase 1.
- **VLAN offload.** Many NICs strip the outer VLAN tag into metadata before
  XDP runs (`rx-vlan-offload`). On those, frames look untagged to the program
  and `l2_vlan*` stay 0. Disable with `ethtool -K <if> rxvlan off` if VLAN
  visibility matters; a metadata kfunc can be used later.
- **Single-buffer XDP.** The program is `SEC("xdp")`, so the kernel refuses
  to attach it to a device whose MTU needs multi-buffer XDP (jumbo frames on
  many drivers). Fine for the lab's 1500-byte MTU.
- **Parse depth.** At most 2 VLAN tags and 6 IPv6 extension headers; deeper
  frames are classified `UNSUP_*` and passed.
- **No reassembly.** Non-first fragments carry no ports; they are counted
  under `frag_later` with their L4 protocol from the IP header.
- **Unaligned loads.** The parser reads wire structs in place. That is
  fine on x86-64 and arm64 (the tested architectures). Strict-alignment
  architectures are not supported.
- **Agent/worker** only validate configuration.
- **Verified environments:** kernel 7.0.14-linuxkit arm64 (Docker Desktop) and
  macOS (host tests). The x86-64 CI job and the Proxmox VM still have to be
  run for the first time.
