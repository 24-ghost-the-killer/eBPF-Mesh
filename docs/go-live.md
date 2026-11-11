# Go-live runbook (phase 10)

Nothing here is done without the project owner's explicit go-ahead, and
only for servers we own until operations are mature (spec phase 10).
Lab address ranges must not be used here; the playbooks refuse them.

## 1. Resources (owner)
- [ ] ASN and an IPv4 /24 (and IPv6 /48) through a sponsoring RIPE LIR.
- [ ] RIPE database: `aut-num` (import/export policy towards each upstream),
      `route`/`route6` objects for the prefixes with our ASN as origin.
- [ ] ROAs (RPKI) for each prefix: origin = our ASN, max length = the
      announced length (/24, /48); check with a validator (RIPE RPKI dashboard).
- [ ] Hosting providers that offer BGP sessions; ask for: a default route
      only (we do not need a full table), their ASN and neighbour addresses,
      their prefix filters (they must accept our route objects).
- [ ] 2-3 PoP servers with native-XDP NICs (see `xdp_native_drivers`) and
      kernel 6.x; a management network or VPN; a control-plane host.
- [ ] DNS names: portal (`PORTAL_DOMAIN`), NATS (`NATS_HOSTNAME`, reachable
      from the PoPs' management side only), status page (separate host).

## 2. Control plane
1. `cd deploy/compose && cp .env.example state/.env`, fill in real values.
2. `scripts/init.sh`; keep `state/` backed up somewhere safe (it holds every
   secret). Put each PoP's `state/nats/<pop>.nk` into the Ansible vault.
3. `docker compose --env-file state/.env up -d --build`; check
   `https://<PORTAL_DOMAIN>/api/v1/status`, Grafana through an SSH tunnel.
4. Create the first operator: `docker compose exec api sentinel-api
   create-admin --config /config/api.toml --email ...` (password from
   `SENTINEL_ADMIN_PASSWORD`), log in, enable 2FA.
5. Install `scripts/backup.sh` as a daily job; test a restore.
6. Host the status page (`status-page/`) on its own domain; add its origin
   to `STATUS_PAGE_ORIGIN` before `init.sh` or in `state/config/api.toml`.

## 3. PoPs, dry run first
1. Inventory `deploy/ansible/inventories/<site>/` (copy `example`):
   `sentinel_lab_mode: false`, real ASN/prefixes, upstream neighbours with
   `max_prefix`, `mgmt_cidrs` that include the Ansible host,
   `bgp_export_enabled: false`.
2. `ansible-playbook -i inventories/<site>/hosts.yml playbooks/pop.yml`.
3. On each PoP: `birdc show protocols` (sessions Established),
   `birdc show route export <upstream>` (must be empty in the dry run),
   `sentinelctl stats`, the PoP in the admin panel, Prometheus target up.
4. Run the kill switch and a drain once; watch the acks.

## 4. First announcement: one PoP
1. Re-run the playbook for **one** PoP with `-e bgp_export_enabled=true
   --limit <pop>`.
2. Verify from outside: looking glasses / RIPE RIS show the prefix with our
   origin and RPKI "valid"; traceroutes from a few networks reach the PoP.
3. Protect one of **our own** servers: portal signup, protected IP, tunnel
   script, tunnel test, observe mode for a day, then mitigate.
4. Then the other PoPs, one at a time.

## Rollback
- Withdraw everywhere: re-run with `bgp_export_enabled=false` (or
  `birdc disable anycast4 anycast6` on each PoP).
- Stop dropping without withdrawing: the kill switch (admin panel).
- One PoP: drain (admin panel) or stop its agent (the health check
  withdraws within seconds).
