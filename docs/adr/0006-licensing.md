# 0006 Licensing

**Status:** Accepted (phase 1)

**Context.** The spec does not name a license. The XDP program must declare a
GPL-compatible license to call GPL-only helpers (the SYN-cookie helpers
needed in phase 2 are GPL-only).

**Decision.** `ebpf/`, `tests/bpf/`, `tests/common/`: GPL-2.0-only OR
BSD-2-Clause (the BPF object declares "Dual BSD/GPL"). Everything else:
MIT OR Apache-2.0. Each file carries an SPDX header; texts are in `LICENSES/`.

**Consequences.** Usual kernel-adjacent dual licensing; userspace stays
permissive.
