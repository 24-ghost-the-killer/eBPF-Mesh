# lab/

Reserved for **Phase 4** (anycast lab): a containerlab topology with three
region routers (AS 65001-65003), three PoPs (AS 65010) running BIRD 2 and the
eBPF Mesh dataplane, one customer origin and three traffic generators, plus the
BIRD health check that withdraws the anycast prefix (`birdc disable anycast`)
when XDP is not attached.

Rules that already apply:

- Lab-only addressing: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
  10.0.0.0/8 (and fd00::/8, 2001:db8::/32 for IPv6). Private ASNs only.
- Traffic generators must refuse any target outside those ranges.
- Everything site-specific lives in config files here, never in code.

The whole lab is designed to run inside a single Linux VM (see
docs/running.md, "Linux VM").
