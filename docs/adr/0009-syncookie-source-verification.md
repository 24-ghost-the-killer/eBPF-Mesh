# 0009 SYN cookies verify the source address

**Status:** Accepted (phase 2; approved by the project owner)

**Context.** Spec §5.1 step 8 says: answer SYNs with a cookie SYN-ACK
(`bpf_tcp_raw_gen_syncookie_*`), validate the final ACK
(`bpf_tcp_raw_check_syncookie_*`) "before passing it on". Passing that ACK to
the origin cannot work: the origin never saw the SYN, has no connection, and
answers with RST. The kernel's XDP SYN proxy only works because a stateful
SYNPROXY on the *same host* completes the handshake with the backend and
translates sequence numbers; our origin is remote.

**Decision.** SYN cookies authenticate the *source address*:

1. SYN from an unverified source → XDP rewrites it in place into a SYN-ACK
   (`XDP_TX`) whose ack number is a cookie that is deliberately not
   `client_isn + 1`.
2. A real TCP stack in SYN-SENT answers an unacceptable ACK with
   `RST(seq = SEG.ACK)` and keeps its connection attempt (RFC 793); Linux
   even rearms the SYN retransmit timer to a few milliseconds.
3. XDP validates the cookie in the RST, stores the source in `xs_verified`
   (LRU, TTL `verify_ttl_s`, default 300 s, refreshed by traffic when less
   than half remains) and drops the RST.
4. The retransmitted SYN passes; the origin performs a normal handshake.

Non-SYN TCP from unverified sources is dropped (`drop_unverified`), which also
stops ACK/RST floods. Cookie = SipHash-2-4 (key in `xs_cfg`, random per PoP,
`sentinelctl syncookie rotate`) over (saddr, daddr, sport, dport, time slot of
2^34 ns ≈ 17 s); the current and previous slot are accepted. The kernel
helpers are not used: the RST does not echo the client ISN they need.

Only plain headers are challenged (no IPv4 options, no IPv6 extension headers,
no fragments); such SYNs from unverified sources are dropped. A missing key
fails open (SYNs pass).

**Consequences.** Spoofed SYN floods never reach the origin. A real client
pays one extra round trip per source per TTL (14 ms in the veth test). Clients
behind a NAT share a verification. In observe mode the would-be verdicts are
counted, which shows every non-SYN TCP packet as `drop_unverified` (worst
case), because nothing is ever verified without sending challenges.
