# Sentinel-Edge

An anycast DDoS-protection platform: every Point of Presence (PoP) announces
the same prefix over BGP, an XDP program on the PoP's NIC filters traffic per
customer, and clean packets are tunnelled (IPIP) to the customer's own server.
A Rust agent, analysis workers and a control-plane API coordinate over NATS; a
Next.js portal sits in front of the API.

**Lab only.** Everything uses documentation/private address ranges and private
ASNs. Nothing here is meant to touch the real internet yet.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: repo, CI, XDP parser + per-CPU counters, `sentinelctl` attach/detach/stats | done |
| 2 | Filtering: bogons, allow/blocklists, services, rate limit, SYN cookies, observe/mitigate | done |
| 3 | Tenants and IPIP tunnel delivery, return path, customer script, MTU/MSS | done |
| 4 | PoP agent and NATS: KV config with acks, stats, telemetry, health | done |
| 5 | Control-plane API and PostgreSQL: auth, 2FA, roles, RLS, assets, policy, rules, audit | done |
| 6 | Portal v1: login, 2FA with passkeys, live overview, protected IPs with tunnel script/test, rules | done |
| 7 | Analysis workers: detection, signed decisions, attacks pages, webhooks | done |
| 8 | Anycast lab: containerlab + BIRD, health check, drain, ClickHouse history, admin panel | done |
| 9 | Public website: home, how it works, pricing, status (hosted separately), contact | done |
| 10a | Production deployment prepared: Ansible for PoPs (guard rails, dry run), compose control plane, monitoring, backups, go-live runbook | **done** |
| 10b | Go-live on the real internet | needs the owner's go-ahead and resources |

## What exists today

- **XDP program** (`ebpf/`), in pipeline order:
  1. parse Ethernet, 2 VLAN tags, IPv4/IPv6 (extension headers, fragments),
     TCP/UDP/ICMP; malformed → drop
  2. traffic to the PoP's own IP and IPv6 neighbour discovery → kernel
  3. bogon sources (RFC1918, loopback, multicast, ...) → drop
  4. **asset lookup**: the destination's protected prefix gives tenant,
     origin server and policy; no asset → drop
  5. allowlist (tenant, then global) → deliver, skipping 6-8
  6. blocklist with expiry enforced inside XDP → drop
  7. allowed services (proto + port), fragment policy → drop the rest
  8. per-source token bucket (IPv6 per /64), then SYN-cookie source
     verification ([ADR 0009](docs/adr/0009-syncookie-source-verification.md))
  9. **sample** 1 in N packets (any verdict) into a ring buffer for telemetry
  10. **deliver**: IPIP (IPv4) or 6in4 (IPv6) to the customer's server, `XDP_TX`

  Origins' replies come back through the tunnel to an anycast endpoint; the
  PoP checks they really come from that customer, clamps the TCP MSS and
  forwards them ([ADR 0012](docs/adr/0012-tunnel-delivery-and-return.md)).
  New assets start in **observe** mode: verdicts are counted, everything is
  still delivered. A global kill switch suspends all drops.
- **`sentinel-agent`** (one per PoP): attaches XDP, applies the NATS KV
  buckets (`tenants`, `services`, `rules`, `platform`) to the maps and
  acknowledges every change on `config.ack.<pop>`; publishes `stats.<pop>`,
  sampled flows on `telemetry.<pop>.<shard>` and `health.<pop>`; writes the
  heartbeat file; serves Prometheus metrics; adapts the sampling rate;
  garbage-collects expired entries. NATS with TLS and one nkey user per
  component ([ADR 0014](docs/adr/0014-nats-users-and-permissions.md),
  [ADR 0015](docs/adr/0015-kv-schema-and-agent-ownership.md)).
- **`sentinel-api`** (axum + PostgreSQL): signup with email verification,
  login with argon2id, server-side sessions with CSRF tokens, TOTP 2FA,
  password reset, roles (viewer < admin < owner, platform admin), API keys
  with scopes, Row Level Security as a second safety net, protected-IP
  allocation, per-asset policy, allow/block rules, tunnel scripts, "active
  on X of Y PoPs", members, audit log, public PoP status, admin kill switch.
  Changes reach the PoPs through a transactional outbox into NATS KV.
  OpenAPI at `/api/v1/openapi.json` (snapshot in `docs/openapi.json`)
  ([ADR 0016](docs/adr/0016-api-sessions-rls-outbox.md),
  [ADR 0017](docs/adr/0017-api-shape.md)).
- **`sentinel-worker`** (analysis): per-tenant baselines (EWMA) over exact
  volume from `stats.<pop>` and traffic shape from its telemetry shards;
  detects attacks (two signals high for a few seconds, hysteresis to end),
  classifies the vector, blocks the largest sources of its shards with
  Ed25519-signed, expiring decisions (never allowlisted ones), and reports
  `attack.<tenant>`. The agent verifies every decision (trusted unrevoked
  key from the `keys` KV bucket, signature, 60 s window, replay) before
  writing it to `xs_block`. The API merges workers' reports into attacks,
  records verified decisions, notifies webhooks (Discord, Slack, signed
  HTTP, email; SSRF-protected) and lets platform admins sign their own
  decisions ([ADR 0021](docs/adr/0021-detection-and-signed-decisions.md),
  [ADR 0022](docs/adr/0022-webhooks.md)).
- **Anycast lab** (`lab/`, containerlab): three BIRD regions, three PoPs
  (BIRD + XDP + agent + health check), customer server, clients and bots,
  NATS, PostgreSQL, ClickHouse, API and two workers. PoPs withdraw the
  anycast route when XDP or the agent is unhealthy and can be drained from
  the admin panel (AS-path prepending); workers store flows in ClickHouse
  for per-PoP traffic history ([ADR 0023](docs/adr/0023-anycast-lab-drain-health.md),
  [ADR 0024](docs/adr/0024-traffic-history-clickhouse.md)).
- **Deployment** (`deploy/ansible`, `deploy/compose`): Ansible roles for
  PoP servers with guard rails (no lab/production mixing, import limits,
  export only our prefixes, dry run until go-live, no SSH lock-out),
  firewall, BIRD, agent and health check; a docker compose control plane
  with Caddy TLS, PostgreSQL, ClickHouse, NATS, Prometheus alerts and a
  Grafana dashboard, secret bootstrap and backups; a go-live runbook
  ([docs/go-live.md](docs/go-live.md), [ADR 0026](docs/adr/0026-production-deployment.md)).
- **Public website** (`web/app/(site)`): home with a live PoP map, how it
  works, pricing, status, contact; and a **status page** (`status-page/`,
  static files on its own host) that keeps working when the platform is down
  ([ADR 0025](docs/adr/0025-public-site-and-status-page.md)).
- **Portal** (`web/`, Next.js + Tailwind + shadcn/ui-style components +
  Recharts): signup, email verification, login, password reset, 2FA with
  passkeys or an authenticator app; an overview with a live graph over
  WebSocket (in / delivered / dropped, per PoP); protected IPs with an add
  wizard, the tunnel script (copy/download), "Active on X of Y PoPs" and a
  **tunnel test** run by every PoP through the real tunnel; a rules page with
  observe/mitigate, allowed services, rate limits, SYN cookies and
  allow/block lists; attacks list and detail (graph, top sources, blocked
  sources), active attacks on the overview, attack notifications, traffic
  history per PoP, and an admin panel (PoP health and drain, kill switch,
  tenants, decisions, signing keys). Client
  generated from the OpenAPI document; one origin
  with the API; CSP with nonces and the other security headers; keyboard
  accessible, responsive, dark and light
  ([ADR 0018](docs/adr/0018-portal-architecture.md),
  [ADR 0019](docs/adr/0019-passkeys.md),
  [ADR 0020](docs/adr/0020-tunnel-test.md)).
- **`sentinelctl`**: attach/detach (native XDP, pinned `bpf_link`), stats,
  assets (`asset add/del/list/script`), per-asset policy and services,
  allow/block rules with TTL, PoP config, SYN-cookie key rotation, gc.
- **Customer tunnel script** (`sentinelctl asset script`): tunnel device,
  protected IP on loopback, replies through the tunnel (default) or DSR.
- **`sentinel-gen`**: lab-only SYN/ACK/UDP flood generator with spoofed
  sources; refuses anything outside the lab ranges.
- **Shared ABI** (`ebpf/include/abi.h` ⇄ `crates/common/src/abi.rs`), checked
  for drift by a Rust test that parses the header.
- **Tests**: 284 `BPF_PROG_TEST_RUN` checks (verdicts, exact counters, exact
  output bytes for SYN challenges, tunnel encapsulation, the return path with
  MSS clamping, sampled events), 6 veth/netns suites with real traffic
  (7 suites), Rust unit tests and API integration tests against a real
  PostgreSQL, Vitest, Playwright browser tests against the full lab, CI.

Acceptance tests:
- phase 10a (`make deploy-test`, `make deploy-smoke`): the PoP playbook
  refuses production/lab mixing and SSH lock-out, converges idempotently,
  brings up BIRD, the agent (XDP), firewall and health timer; dry run
  announces nothing, go-live exactly our prefix, a stopped agent withdraws
  it (22 checks, run on the x86_64 VM); the control-plane stack comes up
  from scratch with TLS, security headers, API and database, NATS,
  workers, ClickHouse users, Prometheus, Grafana and a restorable backup
  (21 checks).
- phase 9 (`tests/e2e/site.spec.ts`): every public page renders, passes axe
  in light and dark mode, fits a phone and links to signup; the separate
  status page shows the PoPs and incidents and, with the API unreachable,
  says so and keeps the last known state.
- phase 8 (`make lab-test`, `lab/scripts/acceptance.sh`): in the
  containerlab lab, each region's bot reaches its own PoP (ClickHouse
  flows); draining pop-2 from the admin API, killing pop-3's agent and
  crashing the pop-1 container each move traffic to another PoP while
  clients in all three regions keep getting answers (0 failed requests in
  the reference run); per-PoP history comes from ClickHouse.
- phase 7 (`tests/e2e/attack.spec.ts`): after a customer's normal setup
  (passkey, webhook, protected IP, tunnel, mitigate), a UDP flood from 8 lab
  bots is detected by the worker within seconds; signed decisions block the
  bots at the PoP (thousands of `drop_block`), the customer's server stops
  receiving the flood while HTTP keeps working, the overview and attack
  pages show it with the blocked sources, the webhook receives signed
  `attack.started`/`attack.ended`, and the attack ends on its own, with no
  manual action. `tests/integration/decisions.sh`: the PoP refuses unknown,
  revoked, stale, replayed, tampered and invalid decisions, honours the
  allowlist, keeps decision blocks across KV reconciles, expires them in
  XDP, and PoPs cannot publish decisions.
- phase 6 (`tests/e2e/onboarding.spec.ts`, run by
  `tests/integration/portal_e2e.sh` against the full lab): in Chromium, a
  customer signs up, verifies the email, adds a passkey, protects a server,
  copies the tunnel script, sees the tunnel test fail, runs the script on
  the "origin" namespace, sees the tunnel test pass from the PoP, watches
  real client traffic on the live graph, switches to mitigate, blocks and
  unblocks a client (enforced at the PoP), and logs in again with the
  passkey. `isolation.spec.ts`: customer A gets "not found" for every page,
  API route and the live WebSocket of customer B. `a11y.spec.ts`: axe finds
  no WCAG 2.1 A/AA violations on any portal page in light and dark mode,
  and pages do not scroll sideways on a phone.
- phase 5 (`crates/api/tests/api.rs`): a customer signs up and gets a
  protected IP through the API; a second customer gets 404 for every way of
  reaching it, and RLS hides it at the SQL level even for a non-member who
  names the tenant. `tests/integration/api_e2e.sh` runs the whole platform:
  API signup to traffic through the PoP, policy and rules from the API
  enforced, "active on 1 of 1 PoPs" from the agent's acknowledgement.
- phase 4 (`tests/integration/agent_kv.sh`): with NATS (TLS, nkeys) and the
  agent running, `nats kv put tenants asset.1 ...` makes the protected IP
  work within a second, nothing restarted; policy, services and block rules
  from KV are enforced and acknowledged; a bad document is rejected without
  touching traffic; a killed agent leaves XDP protecting and resyncs on
  restart.
- phase 3 (`tests/integration/tunnel.sh`): a client's HTTP request crosses the
  PoP into an IPIP tunnel; the origin's server log shows the real client IP;
  replies return through the tunnel (or DSR); 1 MiB transfers in both
  directions fit the tunnel, and a customer with the wrong tunnel MTU is
  rescued by the PoP's MSS clamp.
- phase 2 (`tests/integration/synflood.sh`): 80 000 spoofed SYNs never reach
  the origin's TCP stack while a concurrent `curl` gets the page.

## Quick start

On Linux (kernel 6.x, root for the BPF parts):

```sh
sudo apt-get install clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config \
     iproute2 iputils-ping jq curl python3      # plus a Rust toolchain (rustup)
make                          # XDP object + Rust workspace
make test                     # fmt, clippy, unit tests
sudo make test-bpf            # BPF_PROG_TEST_RUN tests
sudo make test-integration    # veth/netns end-to-end tests

C="sudo target/debug/sentinelctl"
$C attach --iface eth0 --pop-ip4 10.10.1.1
$C config set --tunnel-ep4 198.51.100.1 --nexthop-mac 02:00:00:00:00:fe
$C asset add 198.51.100.10/32 --tenant 42 --origin 192.0.2.10     # asset 1
$C asset script 1 > sentinel-tunnel.sh       # run on the customer's server
$C service add --asset 1 --proto tcp --port 443
$C policy set --asset 1 --enforce-services on --syncookies on --pps-per-src 1000
$C stats --watch                             # observe first ...
$C policy set --asset 1 --mitigate on        # ... then enforce
```

The portal (Node.js 24 + pnpm): `make test-web`, then `sudo make test-e2e`
for the browser tests against the lab; see "Running the portal" in the
runbook.

On macOS (Docker Desktop): `make docker-test` runs every suite inside a
privileged Linux container; `make docker-shell` opens a shell there.

See [docs/running.md](docs/running.md) for the full runbook.

## Repository layout

```
ebpf/include/abi.h        shared kernel/userspace structs and constants
ebpf/src/                 XDP program: parse.h, policy.h, syncookie.h, cookie.h,
                          tunnel.h, maps.h
crates/common             ABI mirror, pin layout, prefixes, lab ranges, stats
crates/bpf                Linux access to the XDP program (attach, maps, rules, stats)
crates/ctl                sentinelctl (operator CLI)
crates/agent              sentinel-agent (PoP agent)
crates/api                sentinel-api (control-plane API) + its integration tests
web/                      Next.js public site + portal + admin (app/, components/, lib/api)
status-page/              static status page (hosted separately)
crates/gen                sentinel-gen (lab traffic generator)
crates/worker             sentinel-worker (attack detection, signed decisions)
migrations/postgres       schema + Row Level Security
tests/bpf                 BPF_PROG_TEST_RUN harness, parser and policy suites
tests/api                 throwaway PostgreSQL for the API tests
tests/integration         veth/netns suites (counts, tunnel, live policy, SYN flood,
                          agent + NATS, API end to end, portal end to end)
tests/e2e                 Playwright browser tests (onboarding, attacks, admin, auth,
                          isolation, accessibility)
lab/                      containerlab anycast lab: topology, BIRD configs, scripts
migrations/clickhouse     flows + traffic_1m
deploy/docker             development/test images (+ pinned NATS, Node, containerlab installers)
deploy/health, systemd    PoP health check (timer), agent unit
deploy/ansible            PoP provisioning (roles, guard rails, example inventory)
deploy/compose            control plane (compose, Caddy, Prometheus, Grafana, init/backup)
deploy/nats               NATS server config renderer (users, permissions, TLS)
configs/                  example agent and API configuration
docs/                     architecture, runbook, ADRs
```

## Known limitations (after phase 8)

- Packets that do not fit the uplink MTU after the 20-byte tunnel header are
  dropped (`drop_too_big`); ICMP "fragmentation needed"/"packet too big"
  replies are not generated yet. TCP is covered by MSS handling.
- The PoP clamps the MSS only when it is the first TCP option (after up to 4
  NOPs), which is where common stacks put it.
- The tunnel underlay is IPv4 only (IPv6 protected prefixes use 6in4).
- SYN cookies add one round trip to the first connection of each source per
  TTL; only SYNs without IPv4 options / IPv6 extension headers are challenged.
  In observe mode with SYN cookies on, all non-SYN TCP counts as
  `drop_unverified`.
- An expired longer prefix shadows an active shorter one until `gc` runs
  ([ADR 0011](docs/adr/0011-expiry-and-fail-open.md)).
- The portal has no members/API-key/audit screens yet (the API endpoints
  exist).
- The lab is IPv4 only and runs on one Docker host. Nothing has been
  announced on the real internet (phase 10b). Mail is log-only (no SMTP).
  ClickHouse traffic counts are sampled estimates.
- Detection is statistical (no ML). Only block decisions exist (no per-source
  rate-limit decisions). With several workers, the SYN-rate and new-source
  signals are per worker (volume is exact). Spoofed floods are left to SYN
  cookies and rate limits.
- The overview graph is live only (last two minutes); history from
  ClickHouse (`traffic_1m`) comes with phase 8. Live frames come from the
  PoPs' exact per-tenant counters (`stats.<pop>`), at most 5 s old.
- Passkeys are a second factor, not a passwordless login.
- The tunnel test probes IPv4 /32 assets only, one test per asset every 5 s.
- `web/scripts/edge.mjs` is a development/test proxy; production needs a
  TLS reverse proxy (deployment arrives in phase 8). Mail is file/log only
  (no SMTP yet).
- Health reports BGP as "n/a" (the health check talks to BIRD; the agent
  does not read BGP state yet).

## License

`ebpf/` and the C tests: GPL-2.0-only OR BSD-2-Clause. Everything else:
MIT OR Apache-2.0. See [LICENSE](LICENSE).
