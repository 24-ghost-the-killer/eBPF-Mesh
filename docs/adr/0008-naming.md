# 0008 Binary and pin names

**Status:** Accepted (phase 1)

**Decision.** Binaries: `sentinelctl`, `sentinel-agent`, `sentinel-worker`,
`sentinel-api` (crates `sentinel-ctl`, `sentinel-agent`, `sentinel-worker`,
`sentinel-api`, `sentinel-common`). BPF maps, structs and constants use the
spec's `xs_` / `XS_` prefix. Default pin directory: `/sys/fs/bpf/sentinel`.
Environment variables: `SENTINEL_*`, plus `XS_IFACE` (name used by the
spec's health-check script).
