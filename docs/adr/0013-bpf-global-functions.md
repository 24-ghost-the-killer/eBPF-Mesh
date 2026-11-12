# 0013 BPF program structure: global functions for verifier budget

**Status:** Accepted (phase 3)

**Context.** Until phase 2 everything was `__always_inline` into one
function. The verifier explores every combination of parser paths (VLAN
count, IPv4/IPv6, extension headers) with every policy path; phase 2 already
cost 315k of the 1M-instruction budget, and adding tunnel delivery and the
return path exceeded it.

**Decision.** The main program parses, looks up the asset and dispatches; the
heavy steps are *global* functions (`__attribute__((noinline))`, external
linkage), which the verifier checks once, on their own, with unknown inputs:
`xs_policy_eval`, `xs_deliver`, `xs_return`, `xs_mss_clamp`. Consequences for
the code:

- Every offset a global function reads back from `struct xs_pkt` is bounded
  with `XS_BOUND()`, an inline-asm mask clang cannot remove. A plain C mask
  or range check is optimised away when clang can prove it redundant, and the
  verifier then sees an unbounded register.
- The asset is copied to the stack before the calls (pointer arguments of
  global functions are plain memory, not map values).
- Packet data that needs scanning (TCP options) is copied to the stack with
  `bpf_xdp_load_bytes` and written back with `bpf_xdp_store_bytes`.

**Consequences.** The whole program verifies in ~58k instructions (phase 2:
315k), leaving room for sampling and later features. Requires kernel 5.18+
for `bpf_xdp_load_bytes` / `store_bytes` (spec targets 6.x).
