# 0005 Explicit padding and an IPv6 variant for `xs_event`

**Status:** Accepted (implemented in phase 4: a single 64-byte `xs_event` with IPv4-mapped addresses, a family field and the sample rate)

**Context.** The `xs_event` struct in spec §5.3 is 30 bytes of fields, which
the compiler pads to 32. Implicit padding breaks the "no implicit holes" ABI
rule and can leak uninitialised kernel stack bytes into the ring buffer. It
also cannot carry IPv6 addresses.

**Decision.** Add an explicit `__u16 _pad2` at the end (size asserted as 32)
and define `xs_event6` with 16-byte addresses, or a single struct with an
address-family field and 16-byte addresses (decided in phase 4 by measuring
ring-buffer throughput).

**Consequences.** Shared layout is fully explicit and checked on both sides.
