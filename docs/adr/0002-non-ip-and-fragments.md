# 0002 Non-IP frames pass; non-first fragments are a separate verdict

**Status:** Accepted (phase 1)

**Context.** Spec §5.1 step 1 says "Malformed -> XDP_DROP". Read literally,
anything that is not parseable IP would be dropped, including ARP. The PoP
then cannot resolve its BGP neighbour or NATS server and falls off the
network. The spec also requires fragment test cases but does not say what
happens to fragments: a non-first fragment has no L4 header, so services and
port-based rules cannot be evaluated on it.

**Decision.**
- *Malformed* means "claims to be IPv4/IPv6 (or a VLAN tag) but fails
  validation". Other ethertypes get verdict `PASS_NON_IP` and `XDP_PASS`.
- A first fragment (offset 0, MF set) is parsed like any packet; if it is too
  short for its L4 header it is malformed (tiny-fragment attack).
- A non-first fragment gets verdict `FRAGMENT`. Phase 1 passes it. Phase 2
  adds a per-tenant fragment policy, defaulting to *drop* in mitigate mode
  (most protected services never need fragments, and they are a classic
  flood vector).
- Phase 2 must also keep IPv6 neighbour discovery and link-local traffic to
  the PoP working (explicit pass before the bogon filter).

**Consequences.** ARP/ND keep working. Non-IP floods are not filtered by
XDP; on a PoP uplink they are only possible from the adjacent router.
