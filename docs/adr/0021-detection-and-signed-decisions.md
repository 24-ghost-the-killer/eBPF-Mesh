# 0021 Attack detection, signed decisions and attack records

**Status:** Accepted (phase 7)

**Context.** Spec sections 6-8: workers detect attacks from telemetry and
publish Ed25519-signed decisions with a TTL; agents verify them (known key,
timestamp window, replay) and never block allowlisted sources; workers
publish `attack.<tenant>` events. Telemetry is sharded by source prefix, so
one worker never sees all of a tenant's sources.

**Decision.**
- **Signals.** Volume (pps, bps per tenant) comes from `stats.<pop>`: exact
  counters that every worker receives, so all workers agree on it. Shape
  (SYN rate, new sources per second, protocol mix, top sources and targets)
  comes from the worker's own telemetry shards (queue group per shard).
  Each signal has an exponentially weighted mean and variance (half-life
  3 h by default); a signal is high above max(floor, factor x mean, mean +
  sigma x stddev); before `warmup_s` only the floor applies. Baselines learn
  only outside attacks.
- **Lifecycle.** Start: at least two high signals for `start_after_s`
  seconds. End: no high signal for `end_after_s` seconds. Vector from the
  protocol mix: syn, udp, icmp, ack flood or volumetric.
- **Decisions.** During an attack the worker blocks sources from its shards
  that send at least `min_src_pps` of the attack's protocol, largest first,
  aggregated to /24 (/48) when `aggregate_min_sources` qualify, never
  overlapping an allowlist (read from the `rules` KV bucket), renewed when
  a third of the TTL is left. Spoofed floods with many small sources get no
  decisions: SYN cookies and rate limits handle them. Only `block` is
  implemented; rate-limit decisions are left for later.
- **Signing.** Ed25519 over a canonical encoding: the domain
  `sentinel-edge/decision/v1`, then each field (type, v, id, issuer,
  tenant, src, action, ttl_s, reason, ts) as length-prefixed name/value
  pairs (u32 big endian). Independent of JSON layout; pinned by a test
  vector. Ids are UUIDv7.
- **Trust.** Public keys live in `signing_keys` (API) and are published to
  the KV bucket `keys` (`issuer.<name>`: key + revoked flag). Agents accept
  a decision only from a known, unrevoked issuer with a valid signature,
  `|ts - now| <= 60 s` and an id not seen in the last two windows; src must
  be no wider than /16 (/32 v6) and TTL at most 24 h. A revoked issuer stays
  revoked (a new key needs a new issuer name). Operators register keys with
  `sentinel-api signing-key add` or `POST /admin/signing-keys`.
- **At the PoP.** Accepted blocks go into xs_block(6) with reason
  `decision` and the TTL as expiry (enforced in XDP, removed by gc). The
  rules bucket's reconcile ignores decision entries unless KV describes the
  same key; KV documents may not use the `decision` reason. A decision never
  overrides a manual block and is skipped when it overlaps an allow entry
  of the tenant or a global one. Outcomes are counted in
  `sentinel_decisions_total{result}`.
- **Attacks in the API.** One active attack per tenant. Reports of several
  workers merge: peaks are the maximum (volume is the same on all workers),
  top sources the union, decisions the sum. The attack ends when every
  reporting worker ended it or has been silent for 60 s. Samples per report
  feed the attack graph. The API records decisions after the same
  verification as the agents. The live view carries active attacks.
- **API decisions.** Platform admins can block a source everywhere through
  `POST /admin/decisions`; the API signs with its own key
  (`SENTINEL_DECISION_KEY`, issuer `api`), registered at start-up.
- **NATS.** Workers: subscribe `telemetry.>`, `stats.>`, read KV `rules`;
  publish `attack.>` and `decision.global`. API: also subscribes to
  `attack.>` and `decision.global` and publishes `decision.global`. PoPs
  read `keys` and cannot publish decisions.

**Consequences.** A worker's key can block any tenant's sources for up to
24 h: keys are per worker, revocable, and every decision expires. With
several workers, SYN-rate and new-source signals see only part of the
sources (thresholds are per worker); volume signals are exact.
