# Design decisions

Short records of decisions that shape the code. Newest last. A decision is
changed by adding a new record that supersedes it, not by editing history.

## D-001: C dataplane, Rust userspace with libbpf-rs

The XDP program is C compiled with clang; userspace is a Rust workspace.
libbpf-rs (not aya) loads the object, so the Rust tools and the C test harness
(`test_xdp`, which uses libbpf directly) load the exact same `.o` the same
way. Reconsider if a pure-Rust toolchain becomes more important than one
loader for everything.

## D-002: One ABI header, mirrored with size asserts and a drift test

`ebpf/src/abi.h` is the source of truth. Rust mirrors it in
`userspace/common/src/abi.rs`; sizes are asserted on both sides and a unit test
parses `abi.h` for slot numbers, parse codes, sizes and the ABI version.
Enumerator values are never reused, and structs reserve room for growth,
because pinned maps are reused across upgrades.

## D-003: No vmlinux.h in Phase 0

The parser describes wire formats, not kernel structures, so there is nothing
for CO-RE to relocate. Defining the header structs locally avoids
endian-dependent bitfields and lets the same code compile on the host (macOS
included) for tests. The BPF build uses only UAPI headers + libbpf. CO-RE /
`vmlinux.h` is introduced when a phase needs kernel types.

## D-004: Global-function verification boundary for the parser

`em_parse()` is a global BPF function, verified once; see architecture.md.
Keeps verification cost flat as stages are added after parsing.

## D-005: Netlink XDP attach with explicit mode and compare-and-swap

`bpf_xdp_attach` rather than `bpf_link`: the attachment outlives the process
that made it (the dataplane must not depend on userspace being alive). Mode is
explicit; there is no auto/generic fallback. `UPDATE_IF_NOEXIST` for fresh
attaches; `REPLACE` with the expected old program for upgrade and detach, so
`meshctl` never removes or overwrites a program it did not attach.

## D-006: Per-interface pin directories

`<pin_root>/<iface>/` per interface: two interfaces never share maps by
accident, one can be torn down independently, and `detach` can remove the
whole directory without a hard-coded map list. Pins never contain `.` because
bpffs rejects such names (EPERM).

## D-007: Observe-only Phase 0, exact counter accounting

Phase 0 always returns `XDP_PASS`. Its value is a parser and counters you
can trust: every frame increments exactly one parse-outcome slot and one
verdict slot, and both the host and the kernel tests check the exact slot set
per frame. Later phases' drop decisions build on these classifications.

## D-008: Bogon detection moves to Phase 1

The old xdp-sentinel parser hard-coded a few bogon ranges. On an internet edge
the bogon set is larger (RFC 1918, CGNAT, documentation, reserved) and is
site policy, and in this lab the documentation ranges are the *legitimate*
traffic. So bogons become a configurable LPM-trie filter in Phase 1 instead
of parser logic.

## D-009: `xdp_mode`, not `mode`, in agent config

The attach mode is `xdp_mode` so that a later `mode`/role setting (edge PoP,
lab, ...) cannot collide with it.

## D-010: Per-platform build directories

`build/<os>-<arch>` and `target/<os>-<arch>` keep macOS and Linux-container
artefacts apart when the same checkout is used from both. The root-only make
targets depend on built files rather than phony targets, so `sudo make` never
needs cargo on root's PATH.

## D-011: Licensing

`ebpf/`, `tests/common/`, `tests/bpf/`: GPL-2.0-only OR BSD-2-Clause (the BPF
program must be GPL-compatible for GPL-only helpers such as SYN cookies).
Everything else: MIT OR Apache-2.0.
