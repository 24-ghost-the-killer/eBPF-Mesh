# 0020 Tunnel test: the PoPs ping the protected IP through the tunnel

**Status:** Accepted (phase 6)

**Context.** Onboarding step 5: "the customer runs the script; the portal
tests the tunnel". The API cannot reach customer servers itself, and a test
should exercise the real path: delivery through the IPIP tunnel *and* the
return tunnel.

**Decision.**
- `POST /tenants/{id}/assets/{aid}/tunnel-test` (admin+) sends a NATS
  request on `probe.<pop>` to every PoP seen in the last 30 seconds and
  returns one result per PoP (sent, received, mean RTT, error). At most one
  test per asset every 5 seconds (checked against the audit log, which also
  records each test).
- The request carries **only the asset id** (`{"v":1,"asset":N,"count":3}`,
  unknown fields rejected). The agent looks the asset up in its own BPF maps
  and probes only an origin it has applied from KV, so even a compromised API
  cannot make a PoP send packets to arbitrary hosts. One probe at a time per
  PoP, at most 5 echo requests.
- The agent sends ICMP echo requests with a raw IPIP socket: outer
  PoP IP → origin (as the dataplane delivers), inner PoP IP → protected IP.
  The customer's server decapsulates and answers from the protected IP
  through its return tunnel; XDP validates and decapsulates the reply like
  any return traffic and forwards it towards the PoP's own address, where a
  raw ICMP socket matches identifier, sequence and source. A reply therefore
  proves both directions. (DSR origins answer directly; the reply still
  reaches the PoP IP.)
- NATS permissions: the API may publish `probe.>`; each PoP may subscribe
  to its own `probe.<id>` and answer on reply subjects only
  (`allow_responses`).

**Requirements.** The PoP needs a route to origins (a default route) and its
unicast address must be reachable from the return path, as on any real PoP.
IPv6-only assets are not probed yet.
