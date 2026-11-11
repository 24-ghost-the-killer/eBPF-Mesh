# Running and testing

## Requirements

- Linux kernel 6.x (native XDP, bpf_link for XDP, BPF_PROG_TEST_RUN)
- clang/LLVM, libbpf headers (`libbpf-dev`), `libelf-dev`, `zlib1g-dev`, `pkg-config`
- Rust (version pinned in `rust-toolchain.toml`; rustup picks it up)
- Kernel 5.18+ for `bpf_xdp_load_bytes`/`store_bytes` (6.x recommended)
- For tests: `iproute2` (with libbpf support for `ip link ... xdp obj`),
  `iputils-ping`, `jq`, `curl`, `ethtool`, `openssl`, `python3`, `nsenter`
  (util-linux), `nats-server` and `nats` (`deploy/docker/install-nats.sh`
  installs the pinned versions), PostgreSQL 16+ server binaries (`initdb`)
- For the web app: Node.js 24 LTS and pnpm (`deploy/docker/install-node.sh`
  installs the pinned versions); the browser tests download Chromium via
  Playwright
- bpffs mounted at `/sys/fs/bpf` (systemd does this; otherwise
  `mount -t bpf bpf /sys/fs/bpf`)

## Build and test

```sh
make                         # build/ebpf/xdp_main.o + target/debug/sentinelctl
make test                    # cargo fmt --check, clippy -D warnings, cargo test
make test-api                # API integration tests (throwaway PostgreSQL)
sudo make test-bpf           # 284 BPF_PROG_TEST_RUN checks
sudo make test-integration   # veth_counts, tunnel, policy_live, synflood, agent_kv, api_e2e
make test-web                # web: API client drift, typecheck, Vitest, next build
sudo make test-e2e           # Playwright: onboarding, auth, isolation, accessibility (full lab)
```

`sudo make test-integration` does not build the Rust binaries (cargo is
usually not on root's PATH), so run `make` as your normal user first.

| Integration suite | Proves |
|---|---|
| `veth_counts.sh` | native attach, exact per-verdict counters, generic refused, clean detach |
| `tunnel.sh` | phase 3 acceptance: delivery through the tunnel, the origin sees the real client IP, tunnel return and DSR, 1 MiB both ways, oversize counted, MSS clamp rescues a wrong customer MTU |
| `policy_live.sh` | rate limit, block/allow with TTL and gc, observe vs mitigate, kill switch, services, PoP traffic bypass |
| `api_e2e.sh` | the whole platform: API signup, protected IP, tunnel script, traffic through the PoP, policy and rules from the API enforced, "active on 1 of 1 PoPs" |
| `agent_kv.sh` | phase 4 acceptance: `nats kv put` configures a live PoP; KV policy/services/rules enforced and acked; bad documents rejected safely; stats, telemetry, health, heartbeat, metrics; NATS permissions and TLS; crash, resync, clean stop |
| `synflood.sh` | phase 2 acceptance: a spoofed SYN flood never reaches the server while `curl` succeeds; control run in observe mode |
| `portal_e2e.sh` (`make test-e2e`) | phase 6 acceptance: Playwright drives Chromium through signup, email verification, passkey 2FA, protecting a server, the tunnel script and tunnel test, live traffic, mitigate, block rules, passkey login; TOTP login; security headers; tenant isolation in pages, API and WebSocket; axe accessibility checks (light/dark, phone width) |

### On macOS

```sh
open -a Docker               # Docker Desktop must be running
make docker-test             # all suites in a privileged Linux container
make docker-shell            # interactive shell, repo mounted at /src
```

The integration suites use three network namespaces (internet router +
client, PoP, origin) joined by veth pairs; see `tests/integration/lib.sh`.
They switch off TX checksum offload on the veths: veth leaves checksums
half-computed for "hardware", and XDP_TX would forward them that way. On
Docker Desktop's kernel the origin uses the fallback `tunl0` device
(creating an IPIP device in a namespace has crashed that VM); elsewhere the
generated script creates `sentinel0`. Override with
`SENTINEL_TEST_TUNNEL_DEV`.

Cargo's registry and target directory live in Docker volumes
(`sentinel-cargo`, `sentinel-target`) so Linux artifacts never mix with the
Mac's `target/`; so do `node_modules`, `web/.next`, the pnpm store and
Playwright's browsers. `make docker-test` uses the `sentinel-web` image
(`Dockerfile.web`: the dev image plus Node.js and Chromium's libraries).
Failed browser tests leave traces and screenshots in
`build/e2e-artifacts/` (`pnpm --filter e2e exec playwright show-trace ...`).

## Operating sentinelctl

```sh
# attach (PoP addresses also via XS_POP_IP4 / XS_POP_IP6; MTU is read from the NIC)
sentinelctl attach --iface eth0 --pop-ip4 10.10.1.1 --pop-ip6 2001:db8:100::1
sentinelctl config set --tunnel-ep4 198.51.100.1 --nexthop-mac 02:00:00:00:00:fe
sentinelctl detach --iface eth0

# protect a prefix (new assets observe only)
sentinelctl asset add 198.51.100.10/32 --tenant 42 --origin 192.0.2.10
sentinelctl asset list
sentinelctl asset script 1 [--return tunnel|dsr] > sentinel-tunnel.sh
sentinelctl asset del 1                              # also removes its services

# per-asset policy (by id or exact prefix)
sentinelctl policy show --asset 1
sentinelctl service add --asset 1 --proto tcp --port 443   # omit --port: whole protocol
sentinelctl policy set --asset 1 --enforce-services on --syncookies on \
    --pps-per-src 1000 --burst 2000 --fragments drop
sentinelctl policy set --asset 1 --mitigate on

# what is happening
sentinelctl stats [--watch --interval 1]
sentinelctl --json stats        # {"entries":[{"tenant":42,"verdict":"pass","pkts":..,"bytes":..}]}

# rules (tenant 0 = global; IPv4 or IPv6; /0 is refused)
sentinelctl block add 203.0.113.0/24 --ttl 10m      # blocks always expire
sentinelctl allow add 192.0.2.10 --tenant 42        # permanent unless --ttl
sentinelctl block list | allow list | block del 203.0.113.0/24
sentinelctl gc                                      # remove expired entries

# PoP-wide
sentinelctl config show | config set --verify-ttl 5m | config set --mtu 9000
sentinelctl syncookie rotate
sentinelctl observe on          # KILL SWITCH: count everything, drop nothing
sentinelctl observe off
```

Every flag has an environment equivalent where it makes sense (see
`.env.example`): `XS_IFACE`, `SENTINEL_BPF_OBJ`, `SENTINEL_PIN_DIR`,
`XS_POP_IP4`, `XS_POP_IP6`.

**Onboarding a customer server.** `asset add` with the server's address as
`--origin`; give the customer `asset script <id>`; they run it as root
(`sh sentinel-tunnel.sh`, `... down` to undo; safe to re-run). It creates an
IPIP (or `sit` for IPv6) device with MTU 1480 and no fixed remote, puts the
protected prefix on `lo`, and routes replies from it back through the tunnel
to the anycast tunnel endpoint. `--return dsr` instead lets replies leave
directly with the protected IP as source (needs a provider without BCP38
filtering) and lowers the advertised MSS so client packets fit the tunnel.

**Rolling out a policy.** Configure services and limits in observe mode, watch
`sentinelctl stats` until the `drop_*` counters only show traffic you really
want dropped, then `policy set --asset <id> --mitigate on`. With SYN cookies
on, observe mode counts all non-SYN TCP as `drop_unverified` (nothing is
verified without challenges), so judge those counters only after switching on.

## Running a PoP with sentinel-agent

1. **NATS** (management network, TLS): create a CA and server certificate,
   one nkey per PoP (`sentinel-agent nkey generate --out lab1.nk` prints the
   public key), and render the server config:

   ```sh
   deploy/nats/render-config.py --listen 0.0.0.0:4222 --cert server.pem \
       --key server.key --store /var/lib/nats --admin UADMIN... \
       --pop lab1=ULAB1... > nats.json
   nats-server -c nats.json
   for b in tenants services rules platform; do nats kv add $b --history 5; done
   ```

2. **Agent**: copy `configs/agent.example.toml`, set the PoP id, interface,
   addresses, NATS URL, CA and seed file, then
   `sentinel-agent check-config --config pop.toml` and
   `sentinel-agent run --config pop.toml` (as root; systemd units come with
   phase 8). The agent attaches XDP itself.

3. **Configure through KV** (until the API exists, with the `nats` CLI and
   admin credentials):

   ```sh
   nats kv put tenants asset.1 '{"v":1,"version":1,"asset":1,"tenant":42,
     "prefix":"198.51.100.10/32","origin":"192.0.2.10",
     "policy":{"mode":"mitigate","syncookies":true,"enforce_services":true}}'
   nats kv put services asset.1 '{"v":1,"version":1,"services":[{"proto":"tcp","port":443}]}'
   nats kv put rules tenant.42 '{"v":1,"version":1,"block":[{"prefix":"203.0.113.0/24","expires_at":1762790405000}]}'
   nats kv put platform global '{"v":1,"version":1,"observe":true}'   # kill switch
   nats sub 'config.ack.>'        # every change is acknowledged per PoP
   ```

   The full schema is in ADR 0015. `sentinelctl asset script 1` still
   generates the customer's tunnel script from the applied state.

While the agent runs it owns assets, services, rules and the kill switch:
`sentinelctl` changes to those are overwritten at the next resync (it warns).
Read-only `sentinelctl` commands (`stats`, `asset list`, `config show`, ...)
are always fine.

| Agent output | Where |
|---|---|
| acknowledgements | `config.ack.<pop>` |
| counters + rates, every second | `stats.<pop>` and `http://127.0.0.1:9466/metrics` |
| sampled flows, every second | `telemetry.<pop>.<shard>` |
| health, every 5 s | `health.<pop>` and the heartbeat file |

## Running the API

1. **PostgreSQL 16+.** Create the database and an owner role, run the
   migrations as the owner, then let the API's role log in:

   ```sh
   export SENTINEL_API_CONFIG=configs/api.local.toml        # from api.example.toml
   export SENTINEL_DATABASE_OWNER_URL=postgres://sentinel_owner:...@db/sentinel
   sentinel-api migrate                                     # creates role sentinel_api (NOLOGIN)
   psql ... -c "ALTER ROLE sentinel_api LOGIN PASSWORD '...'"
   ```

   The owner needs `CREATEROLE` for the first migration (or create
   `sentinel_api` yourself beforehand).

2. **Secrets** (environment, never files in git):
   `SENTINEL_DATABASE_URL` (role `sentinel_api`), `SENTINEL_DATA_KEY`
   (`head -c 32 /dev/urandom | base64`; encrypts TOTP secrets: keep it,
   losing it disables everyone's 2FA).

3. **NATS:** give the API its own nkey user (`render-config.py --api U...`);
   it may write the KV buckets and read acknowledgements and health.

4. `sentinel-api serve`, behind TLS (a reverse proxy; then set
   `trust_proxy = true`). First operator:
   `SENTINEL_ADMIN_PASSWORD=... sentinel-api create-admin --email ops@example.org`,
   then enable 2FA before using `/admin/*`.

`sentinel-api openapi` prints the OpenAPI document; after changing
endpoints regenerate the snapshot with
`UPDATE_OPENAPI=1 cargo test -p sentinel-api --test openapi`, then the web
client with `pnpm --filter web gen:api`.

## Running the portal (web app)

The portal is a Next.js app in `web/` that only talks to the API, under the
same origin ([ADR 0018](adr/0018-portal-architecture.md)):

```sh
pnpm install
pnpm --filter web build && pnpm --filter web start      # Next.js on 127.0.0.1:3001
EDGE_LISTEN=127.0.0.1:3000 API_ORIGIN=http://127.0.0.1:8080 \
  WEB_ORIGIN=http://127.0.0.1:3001 node web/scripts/edge.mjs   # one origin for both
```

- The API's `server.public_url` must be the URL users open (passkeys are
  bound to its host; WebSocket origins are checked against it; mail links
  point there). Set `trust_proxy = true` behind the edge proxy or any
  reverse proxy that overwrites `X-Forwarded-For`.
- `edge.mjs` is for development and tests. In production put a TLS reverse
  proxy in front that routes `/api/v1/` (with WebSocket upgrades) to the API
  and everything else to Next.js; the portal then sends HSTS.
- Browsers treat `http://localhost` as secure, so `cookie_secure = true`
  works there; other plain-HTTP lab hosts need `cookie_secure = false`, and
  passkeys need HTTPS or localhost.
- Tunnel tests need the PoPs online and connected to NATS, a route from each
  PoP to the origins, and the API allowed to publish `probe.>`
  (`render-config.py` does this; [ADR 0020](adr/0020-tunnel-test.md)).

## sentinel-gen (lab traffic generator)

```sh
sentinel-gen syn --dst 198.51.100.10 --dport 80 --src 203.0.113.128/25 --duration 5s --pps 20000
sentinel-gen udp --dst 198.51.100.10 --dport 53 --src 203.0.113.50 --count 3000
sentinel-gen ack --dst 2001:db8:100::10 --src 2001:db8:100:ff::/64 --count 1000
```

Each packet uses a random source from `--src`. Destination and sources must be
inside the lab ranges (spec §11.1); `--allow-non-lab-destination` disables the
check and prints a warning. Needs root (raw sockets).

### Generic mode

`--mode generic` is refused unless `--allow-generic` is also given. Generic
XDP runs after the kernel allocates an skb and is far too slow for a PoP; use
it only for tests on drivers without native XDP.

### Network namespaces

`ifindex` lookup and the XDP link are relative to the caller's network
namespace, so run `sentinelctl` inside the namespace that owns the interface.
Use `nsenter --net=/run/netns/<ns> sentinelctl ...`, **not**
`ip netns exec <ns> ...`: the latter remounts `/sys` in a private mount
namespace, which hides bpffs at `/sys/fs/bpf`, and attach fails with
"creating /sys/fs/bpf/sentinel: No such file or directory".

### VLANs on physical NICs

The parser handles in-band VLAN tags. Many NICs strip the outer tag before
XDP sees it (rx-vlan offload). On a PoP with tagged uplinks, disable it:
`ethtool -K <iface> rxvlan off`. See
[ADR 0003](adr/0003-vlan-offload.md).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `driver does not support native XDP` | NIC driver lacks XDP; pick another NIC (generic only for tests) |
| `another XDP program is already attached` | `ip link show dev <iface>`; remove the other program first |
| `already attached to <iface>` | a pinned link exists; `sentinelctl detach --iface <iface>` |
| `is not on bpffs` | `mount -t bpf bpf /sys/fs/bpf` |
| `loading ... incompatible build` | pinned maps from an older ABI; detach every interface, then attach again |
| `XDP program is not attached` (stats) | nothing attached with this `SENTINEL_PIN_DIR` |
| clients hang ~1 s on first connect | SYN cookies on and the client never answers the challenge with RST (some middleboxes drop it); allowlist the client network |
| `syncookie key MISSING` in `config show` | maps were created by an old build; detach and attach again (SYNs pass meanwhile) |
| `drop_no_tenant` for a customer's traffic | no asset covers the destination: `asset list` |
| `drop_tunnel` | no PoP IPv4 configured (`config set --pop-ip4`) |
| `drop_too_big` | packets above uplink MTU − 20; check the customer's MSS / tunnel MTU 1480 |
| `drop_return` | replies from an unregistered origin, or with a source that is not that origin's asset |
| API answers 404 for a tenant you belong to | session expired (idle 1 h) or the role is missing; check `GET /me` |
| API `403 csrf` | send the `csrf_token` from login or `/me` as `X-CSRF-Token` |
| asset status stays "0 of N PoPs" | outbox not drained (NATS down? `kv_outbox` rows) or the agent rejected the document (`config_acks.error`) |
| `rejected: ...` in the agent log / `"ok":false` acks | the KV document failed validation; the previous state is kept |
| agent: `KV sync stopped ... retrying` | NATS unreachable or bucket missing; XDP keeps the last state |
| `sampled_events_lost` rising | ring buffer full: raise `sample_base` |
| customer sees nothing in the tunnel | provider filters IP protocol 4/41, or rp_filter on the origin; the script turns rp_filter off |
