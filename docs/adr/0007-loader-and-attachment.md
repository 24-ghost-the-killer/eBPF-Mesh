# 0007 libbpf-rs loader, pinned bpf_link per interface

**Status:** Accepted (phase 1)

**Context.** The spec allows libbpf-rs or aya. The dataplane is C built with
clang and libbpf conventions (`SEC(".maps")`, BTF-defined maps, CO-RE later).
`sentinelctl attach` must leave the program running after it exits, and must
refuse generic mode unless explicitly allowed.

**Decision.**
- Load with libbpf-rs (libbpf itself handles the object; no reimplementation
  of ELF/BTF loading).
- Attach with an XDP `bpf_link` created with explicit mode flags
  (`XDP_FLAGS_DRV_MODE` / `XDP_FLAGS_SKB_MODE`) and pin it at
  `$SENTINEL_PIN_DIR/link_xdp_<ifname>`. libbpf's `bpf_program__attach_xdp`
  takes no flags, so `bpf_link_create` is called through libbpf-sys.
- Maps are pinned by name under `$SENTINEL_PIN_DIR` and reused by later loads
  (and, in phase 4, by the agent).
- On Linux only; on other OSes the CLI compiles but every command reports
  that it needs Linux, so `cargo test` runs on developer Macs.
- Run the CLI inside a netns with `nsenter --net`, not `ip netns exec`, which
  hides bpffs (see docs/running.md).

**Consequences.** A pinned link cannot be replaced by another loader by
accident and is removed atomically by `detach`. Upgrading the program in
place (`bpf_link_update`) is possible later without a detach gap.
