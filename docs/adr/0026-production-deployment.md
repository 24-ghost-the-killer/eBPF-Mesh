# 0026 Production deployment and go-live guard rails

**Status:** Accepted (phase 10a; go-live itself needs the owner's explicit
go-ahead, spec phase 10)

**PoP servers: Ansible** (`deploy/ansible`, `playbooks/pop.yml`):
`sentinel_preflight`, `sentinel_firewall`, `sentinel_bird`,
`sentinel_agent`, `sentinel_health`. Secrets (each PoP's NATS nkey seed)
come from Ansible Vault; real inventories live outside git
(`inventories/<site>/`, git-ignored except `example`).

**Guard rails** (refused before anything changes on the host):
- Lab and production never mix: `sentinel_lab_mode: true` allows only
  documentation/private prefixes and private ASNs; production refuses them
  and accepts only prefixes the internet takes (IPv4 /24 or shorter, IPv6
  /48 or shorter).
- Every upstream needs a `max_prefix` (BIRD `import limit ... action
  disable`); we import only a default route.
- The export filter announces only our own prefixes, only from the anycast
  static protocols, and only when `EXPORT = 1`. `bgp_export_enabled`
  defaults to false: **dry run** (sessions up, nothing announced) until
  go-live, which is a separate, deliberate playbook run.
- The PoP's own address may not lie inside an announced prefix.
- The firewall may not lock out the Ansible control host (its address must be
  inside `mgmt_cidrs`); rulesets are validated with `nft -c` before use and
  live in their own table (`inet sentinel`).
- Kernel 6.x and a driver with native XDP (generic only when explicitly
  allowed for labs); the agent config is validated before restart; BIRD
  configs are validated with `bird -p` before they replace the old one.

**Control plane: docker compose** (`deploy/compose`): Caddy (TLS via ACME,
one origin for portal and API), the portal, the API, two workers,
PostgreSQL, ClickHouse, NATS (TLS, one user per component), Prometheus
(agents via file_sd, Caddy; alert rules) and Grafana (provisioned dashboard,
login required, bound to localhost). `scripts/init.sh` generates every secret
into `state/` (mode 700, never overwritten); a one-shot bootstrap runs the
migrations and trusts the workers' keys; another creates the KV buckets.
Images: pinned base images at least two weeks old, our binaries built
in-image (`Dockerfile.control`, `Dockerfile.portal`), non-root users.
`scripts/backup.sh` dumps PostgreSQL with retention and a restore check.

**Tests.** `make deploy-test` runs the PoP playbook against a systemd
container with a BIRD "upstream" (guard rails, idempotence, services, XDP,
dry run vs go-live, health-check withdrawal, firewall); `make deploy-smoke`
brings the whole compose stack up from scratch. Both run in CI; the PoP
test was run on the project's x86_64 VM (kernel 7.0).
