# 0010 ICMP errors bypass the allowed-services list

**Status:** Accepted (phase 2)

**Context.** With services enforced, a policy allowing only `tcp/443` would
drop ICMP "fragmentation needed" and ICMPv6 "packet too big" sent to the
protected IP. Those belong to traffic the origin itself sent; dropping them
black-holes path MTU discovery (especially relevant with the 20-byte IPIP
overhead of phase 3).

**Decision.** ICMP types 3, 11, 12 and ICMPv6 types 1-4 pass the services
check. Allowlist, blocklist and the per-source rate limit still apply.

**Consequences.** PMTUD keeps working. ICMP error floods are bounded by the
per-source rate limit and blocks, not by the services list.
