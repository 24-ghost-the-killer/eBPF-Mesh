# 0023 Anycast lab, draining and the PoP health check

**Status:** Accepted (phase 8)

**Lab.** `lab/topology.clab.yml` (containerlab) builds the topology of spec
11.5: three "internet" regions (BIRD, AS 65001-65003, full mesh), three PoPs
(BIRD AS 65010 + XDP + agent + health check), a customer server, clients
and bots per region, and NATS, PostgreSQL, ClickHouse, the API and two
workers on a management network (172.31.250.0/24). Everything but ClickHouse
uses one image (`lab/Dockerfile`); Sentinel binaries and XDP objects are
bind-mounted from `build/lab`. `lab/scripts/setup.sh` generates every secret
and config into `lab/state` (git-ignored).

On a Mac the lab runs on Docker Desktop: `make lab-up|lab-test|lab-down`
start containerlab inside the test image with the host's Docker socket,
host network and PID namespace, and the repository mounted at the same path
as on the host (containerlab bind mounts are host paths).

**Deviations from the spec's example.**
- The PoP's BGP neighbour is on 10.10.N.0/24 and the PoP's unicast address
  (agent `pop_ip4`) is its uplink address: XDP lets traffic to `pop_ip4`
  through before the bogon filter, so BGP from a private address works.
- Lab links use MTU 1500 (containerlab's default 9500 is refused by veth
  XDP); BGP uses hold time 3 s; IPv4 only in the lab.
- Region routers attach a pass-through XDP program to their PoP-facing veth
  (veth XDP_TX needs a program on the peer).

**Draining.** `POST /admin/pops/{id}/drain` (platform admin, audited) sets
the PoP to `draining` and writes KV `platform/pop.<id>` = `{"drain": bool}`.
The agent of that PoP writes its drain include (`define DRAIN = 0|1;`)
atomically and runs `birdc configure`; the BIRD export filter prepends 65010
twice when DRAIN = 1, so regions prefer other PoPs. KV keeps the setting
across agent restarts. Agents without `[bird]` refuse it (ack with error).

**Health check.** `deploy/health/sentinel-health.sh` (systemd timer every
2 s; a loop in the lab) disables the anycast static protocols when XDP is not
attached to the uplink or the agent heartbeat is older than 10 s, and
enables them again when both are healthy. A crashed agent leaves XDP
attached (pinned link), so traffic keeps flowing until the route is
withdrawn: no loss. A stopped agent detaches XDP first; use `--keep-attached`
for upgrades.

**Acceptance (`make lab-test`).** Each bot's traffic arrives at its own
region's PoP (ClickHouse flows); draining pop-2, killing pop-3's agent and
crashing the pop-1 container move traffic while clients in all regions keep
getting answers (the run counts every failed request).
