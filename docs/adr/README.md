# Architecture Decision Records

One file per decision: context, decision, consequences. Status is
*Accepted*, *Proposed* (agreed direction, implemented in a later phase) or
*Superseded by NNNN*. Never rewrite an accepted ADR; supersede it.

| # | Title | Status |
|---|---|---|
| [0001](0001-record-decisions.md) | Record decisions as ADRs | Accepted |
| [0002](0002-non-ip-and-fragments.md) | Non-IP frames pass; non-first fragments are a separate verdict | Accepted (fragment policy implemented in phase 2) |
| [0003](0003-vlan-offload.md) | Parse in-band VLAN tags; disable rx-vlan offload on PoPs | Accepted |
| [0004](0004-per-asset-bpf-policy.md) | BPF policy is per protected prefix (asset), not per tenant | Accepted |
| [0005](0005-xs-event-layout.md) | Explicit padding and an IPv6 variant for `xs_event` | Accepted |
| [0006](0006-licensing.md) | Licensing | Accepted |
| [0007](0007-loader-and-attachment.md) | libbpf-rs loader, pinned bpf_link per interface | Accepted |
| [0008](0008-naming.md) | Binary and pin names | Accepted |
| [0009](0009-syncookie-source-verification.md) | SYN cookies verify the source address | Accepted |
| [0010](0010-icmp-errors-bypass-services.md) | ICMP errors bypass the allowed-services list | Accepted |
| [0011](0011-expiry-and-fail-open.md) | Expiry clock and fail-open defaults | Accepted |
| [0012](0012-tunnel-delivery-and-return.md) | Tunnel delivery and the return path | Accepted |
| [0013](0013-bpf-global-functions.md) | BPF program structure: global functions for verifier budget | Accepted |
| [0014](0014-nats-users-and-permissions.md) | NATS: one user per component, TLS everywhere | Accepted |
| [0015](0015-kv-schema-and-agent-ownership.md) | KV schema, versioning and agent ownership of maps | Accepted |
| [0016](0016-api-sessions-rls-outbox.md) | API: sessions, CSRF, Row Level Security, outbox | Accepted |
| [0017](0017-api-shape.md) | API shape: per-asset policy and onboarding details | Accepted |
| [0018](0018-portal-architecture.md) | Portal architecture: same origin, client rendering, generated client | Accepted |
| [0019](0019-passkeys.md) | Passkeys as a second factor | Accepted |
| [0020](0020-tunnel-test.md) | Tunnel test: the PoPs ping the protected IP through the tunnel | Accepted |
| [0021](0021-detection-and-signed-decisions.md) | Attack detection, signed decisions and attack records | Accepted |
| [0022](0022-webhooks.md) | Attack notifications (webhooks) | Accepted |
