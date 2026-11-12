# 0014 NATS: one user per component, TLS everywhere

**Status:** Accepted (phase 4)

**Context.** Spec §10 asks for "NATS with TLS and one account per
PoP/worker/API, each allowed to publish and subscribe only to its own
subjects". In NATS, *accounts* are isolated subject spaces: two accounts
cannot exchange a single message without an export/import declaration for
every subject. PoPs, workers and the API constantly talk to each other
(telemetry, decisions, acks), and all of them read the same KV buckets.

**Decision.** One NATS account; **one user per component**, identified by
its own nkey (Ed25519; `sentinel-agent nkey generate`), with subject
permissions that give exactly the isolation the spec asks for:

| User | Publish | Subscribe |
|---|---|---|
| PoP `<id>` | `telemetry.<id>.>`, `stats.<id>`, `health.<id>`, `config.ack.<id>`; read-only KV API for `tenants`, `services`, `rules`, `platform` | `decision.global`, `_INBOX.>` |
| admin | everything | everything |

Workers (phase 7) and the API (phase 5) get their own users the same way.
A PoP cannot write KV (`$KV.*` is not allowed), cannot impersonate another
PoP, and cannot read other PoPs' telemetry. TLS is required (`tls {}` block;
plaintext clients are refused); the CA verifies the server. The config is
rendered by `deploy/nats/render-config.py`; seeds stay in files outside git.

**Consequences.** Revoking a PoP = removing its user. The integration test
checks: PoP KV write refused, publishing another PoP's stats refused,
plaintext refused. Moving to operator mode (JWT accounts) later remains
possible without changing subjects.
