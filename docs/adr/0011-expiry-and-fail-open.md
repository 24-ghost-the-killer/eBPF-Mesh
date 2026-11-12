# 0011 Expiry clock and fail-open defaults

**Status:** Accepted (phase 2)

**Decision.**
- Every expiry (`xs_rule.expires_ns`, `xs_verified`) is CLOCK_BOOTTIME
  nanoseconds: `bpf_ktime_get_boot_ns()` in XDP, `clock_gettime(CLOCK_BOOTTIME)`
  in userspace. It keeps counting during suspend and never jumps with NTP.
- Expiry is enforced inside XDP; userspace only garbage-collects
  (`sentinelctl gc`, later the agent). If userspace dies, blocks still expire.
- Fail open when configuration is missing: a block without expiry is never
  active, a missing SYN-cookie key lets SYNs pass, a missing policy passes.
- Bogon and malformed drops are global (they happen before the tenant is
  known) and are suspended only by the kill switch (`sentinelctl observe on`).

**Known limitation.** LPM tries return only the longest match: an expired
longer prefix shadows an active shorter one for the same source until `gc`
removes it. The agent (phase 4) runs gc every few seconds.
