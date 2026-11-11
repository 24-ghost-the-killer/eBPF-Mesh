# Architecture Decision Records

One file per decision: context, decision, consequences. Status is
*Accepted*, *Proposed* (agreed direction, implemented in a later phase) or
*Superseded by NNNN*. Never rewrite an accepted ADR; supersede it.

| # | Title | Status |
|---|---|---|
| [0001](0001-record-decisions.md) | Record decisions as ADRs | Accepted |
| [0002](0002-non-ip-and-fragments.md) | Non-IP frames pass; non-first fragments are a separate verdict | Accepted (fragment policy implemented in phase 2) |
| [0003](0003-vlan-offload.md) | Parse in-band VLAN tags; disable rx-vlan offload on PoPs | Accepted |
| [0004](0004-per-asset-bpf-policy.md) | BPF policy is per protected prefix (asset), not per tenant | Proposed (phase 3) |
| [0005](0005-xs-event-layout.md) | Explicit padding and an IPv6 variant for `xs_event` | Proposed (phase 4) |
| [0006](0006-licensing.md) | Licensing | Accepted |
| [0007](0007-loader-and-attachment.md) | libbpf-rs loader, pinned bpf_link per interface | Accepted |
| [0008](0008-naming.md) | Binary and pin names | Accepted |
| [0009](0009-syncookie-source-verification.md) | SYN cookies verify the source address | Accepted |
| [0010](0010-icmp-errors-bypass-services.md) | ICMP errors bypass the allowed-services list | Accepted |
| [0011](0011-expiry-and-fail-open.md) | Expiry clock and fail-open defaults | Accepted |
