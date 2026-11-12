// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Tenant lookup, tunnel delivery and the return path:
 *  - asset lookup (longest prefix, per-tenant counters, no tenant)
 *  - IPIP / 6in4 encapsulation with exact output bytes (DSCP copy, VLAN,
 *    next-hop MAC), MTU limit, missing PoP IP
 *  - per-asset policies and services
 *  - return path: validation, MSS clamp with exact bytes and a valid TCP
 *    checksum, decapsulation
 */
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <bpf/bpf.h>

#include "harness.h"

#define ETH_IP 0x0800
#define ETH_IP6 0x86DD
#define ETH_VLAN 0x8100
#define ETH_QINQ 0x88A8

static const uint8_t NH_MAC[6] = { 0x02, 0, 0, 0, 0, 0xfe };
static const uint8_t ORIGIN2[4] = { 192, 0, 2, 20 };
static const uint8_t DST4_B[4] = { 198, 51, 100, 11 };
static const uint8_t NET24[4] = { 198, 51, 100, 0 };

static void set_ip4(struct pkt *p, size_t at, const uint8_t a[4])
{
	memcpy(p->b + at, a, 4);
}

/* UDP to dst with an IP packet of exactly ip_len bytes. */
static size_t udp4_len(struct pkt *p, const uint8_t dst[4], size_t ip_len)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0);
	udp(p, 5353, 53, ip_len - 28);
	fix_ipv4_len(p, ip);
	set_ip4(p, ip + 16, dst);
	return ip;
}

static size_t udp6_len(struct pkt *p, size_t ip_len)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_UDP);
	udp(p, 5353, 53, ip_len - 48);
	fix_ipv6_len(p, ip);
	return ip;
}

static size_t tcp4_to(struct pkt *p, const uint8_t dst[4], uint16_t dport)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 5, 0);
	tcp(p, 40000, dport, TCP_SYN, 5);
	fix_ipv4_len(p, ip);
	set_ip4(p, ip + 16, dst);
	return ip;
}

static void delivered(const char *name, const struct pkt *in, size_t l3,
		      const uint8_t origin[4], const uint8_t *mac, int verdict)
{
	struct pkt out, want;
	char label[96];

	expect(name, in, XDP_TX, verdict, &out);
	expected_encap(&want, in, l3, origin, mac);
	snprintf(label, sizeof(label), "%s/exact-bytes", name);
	check_bytes(label, &out, &want);
}

static void lookup_and_delivery(void)
{
	struct xs_cfg c = { 0 };
	struct pkt p;
	size_t ip;
	uint64_t before;

	printf("# asset lookup and tunnel delivery\n");
	reset_state();

	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 60);
	delivered("deliver/ipv4 udp -> ipip", &p, 14, TEST_ORIGIN, NULL, XS_V_PASS);
	p.b[15] = 0xb8; /* DSCP EF + ECT(0) */
	delivered("deliver/ipv4 tos copied to outer", &p, 14, TEST_ORIGIN, NULL, XS_V_PASS);

	p = (struct pkt){ 0 };
	eth(&p, ETH_IP6);
	ip = ipv6(&p, IPPROTO_TCP);
	tcp(&p, 40000, 443, TCP_SYN, 10);
	fix_ipv6_len(&p, ip);
	p.b[ip] = 0x62; /* traffic class 0x2e */
	p.b[ip + 1] = 0xe0;
	delivered("deliver/ipv6 tcp -> 6in4, tclass copied", &p, 14, TEST_ORIGIN, NULL,
		  XS_V_PASS);

	p = (struct pkt){ 0 };
	eth(&p, ETH_QINQ);
	vlan(&p, 200, ETH_VLAN);
	vlan(&p, 100, ETH_IP);
	ip = ipv4(&p, IPPROTO_UDP, 5, 0);
	udp(&p, 1000, 53, 16);
	fix_ipv4_len(&p, ip);
	delivered("deliver/QinQ tags kept", &p, 22, TEST_ORIGIN, NULL, XS_V_PASS);

	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 42);
	put(&p, NULL, 60 - p.len); /* Ethernet padding travels along, ignored */
	delivered("deliver/padded frame", &p, 14, TEST_ORIGIN, NULL, XS_V_PASS);

	memcpy(c.nexthop_mac, NH_MAC, 6);
	set_cfg(&c);
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 60);
	delivered("deliver/configured next-hop MAC", &p, 14, TEST_ORIGIN, NH_MAC, XS_V_PASS);

	/* Longest prefix wins; counters go to the owning tenant. */
	add_asset4(NET24, 24, 9, 3, ORIGIN2, 0);
	before = stat_pkts(9, XS_V_PASS);
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4_B, 60);
	delivered("lookup/198.51.100.11 -> /24 asset", &p, 14, ORIGIN2, NH_MAC, XS_V_PASS);
	check("lookup/counted under tenant 9", stat_pkts(9, XS_V_PASS) == before + 1,
	      "tenant 9 pass counter did not move");
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 60);
	delivered("lookup/198.51.100.10 -> more specific /32", &p, 14, TEST_ORIGIN, NH_MAC,
		  XS_V_PASS);

	p = (struct pkt){ 0 };
	udp4_len(&p, (const uint8_t[4]){ 198, 51, 101, 1 }, 60);
	before = stat_pkts(0, XS_V_DROP_NO_TENANT);
	expect("lookup/no asset dropped", &p, XDP_DROP, XS_V_DROP_NO_TENANT, NULL);
	check("lookup/no-tenant counted under tenant 0",
	      stat_pkts(0, XS_V_DROP_NO_TENANT) == before + 1, "not under tenant 0");
	c.flags = XS_CFG_F_OBSERVE;
	set_cfg(&c);
	expect("lookup/no asset, kill switch: to the kernel", &p, XDP_PASS,
	       XS_V_DROP_NO_TENANT, NULL);

	c = (struct xs_cfg){ 0 };
	set_cfg_raw(&c); /* no PoP IP */
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 60);
	expect("deliver/without PoP IP: drop_tunnel", &p, XDP_DROP, XS_V_DROP_TUNNEL, NULL);
}

static void mtu(void)
{
	struct xs_cfg c = { 0 };
	struct pkt p;

	printf("# MTU\n");
	reset_state();
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 1480);
	delivered("mtu/1480-byte packet fits 1500", &p, 14, TEST_ORIGIN, NULL, XS_V_PASS);
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 1481);
	expect("mtu/1481-byte packet too big", &p, XDP_DROP, XS_V_DROP_TOO_BIG, NULL);
	p = (struct pkt){ 0 };
	udp6_len(&p, 1481);
	expect("mtu/ipv6 1481 too big", &p, XDP_DROP, XS_V_DROP_TOO_BIG, NULL);
	c.uplink_mtu = 9000;
	set_cfg(&c);
	p = (struct pkt){ 0 };
	udp4_len(&p, DST4, 1481);
	delivered("mtu/uplink mtu 9000", &p, 14, TEST_ORIGIN, NULL, XS_V_PASS);
}

static void per_asset(void)
{
	struct xs_cfg c = { 0 };
	struct pkt p;

	printf("# per-asset policies\n");
	reset_state(); /* default assets: observe */
	add_asset4(DST4_B, 32, 9, 3, ORIGIN2, XS_P_MITIGATE | XS_P_SERVICES);
	add_service_for(3, IPPROTO_TCP, 80);

	p = (struct pkt){ 0 };
	tcp4_to(&p, DST4_B, 80);
	delivered("asset/B tcp 80 allowed", &p, 14, ORIGIN2, NULL, XS_V_PASS);
	p = (struct pkt){ 0 };
	tcp4_to(&p, DST4_B, 443);
	expect("asset/B tcp 443 dropped (B's services)", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	p = (struct pkt){ 0 };
	tcp4_to(&p, DST4, 443);
	delivered("asset/A in observe: delivered", &p, 14, TEST_ORIGIN, NULL, XS_V_PASS);

	set_policy(XS_P_MITIGATE | XS_P_SERVICES, 0, 0);
	expect("asset/A mitigating, B's service does not apply", &p, XDP_DROP,
	       XS_V_DROP_SERVICE, NULL);
	set_policy(XS_P_SERVICES, 0, 0);
	delivered("asset/A observe: drop counted, delivered", &p, 14, TEST_ORIGIN, NULL,
		  XS_V_DROP_SERVICE);

	c.flags = XS_CFG_F_OBSERVE;
	set_cfg(&c);
	p = (struct pkt){ 0 };
	tcp4_to(&p, DST4_B, 443);
	delivered("asset/kill switch: B still delivered", &p, 14, ORIGIN2, NULL,
		  XS_V_DROP_SERVICE);
	p = (struct pkt){ 0 };
	{
		size_t ip = udp4_len(&p, DST4_B, 60);

		set_ip4(&p, ip + 12, (const uint8_t[4]){ 10, 0, 0, 1 });
	}
	delivered("asset/kill switch: bogon counted, delivered", &p, 14, ORIGIN2, NULL,
		  XS_V_DROP_BOGON);
}

/* ---- return path ------------------------------------------------------------ */

/* IPIP from outer_src to the tunnel endpoint; inner IPv4 TCP from inner_src
 * port 443 to 203.0.113.7:40000 with the given flags and options. Returns the
 * inner IP offset. */
static size_t ret4(struct pkt *p, uint16_t ethertype_vlan, const uint8_t outer_src[4],
		   const uint8_t inner_src[4], uint8_t flags, const uint8_t *opts,
		   size_t optlen)
{
	size_t o, i, l3;

	if (ethertype_vlan) {
		eth(p, ETH_VLAN);
		vlan(p, ethertype_vlan, ETH_IP);
	} else {
		eth(p, ETH_IP);
	}
	l3 = p->len;
	o = ipv4(p, IPPROTO_IPIP, 5, 0);
	i = ipv4(p, IPPROTO_TCP, 5, 0);
	tcp(p, 443, 40000, flags, 5 + (optlen + 3) / 4);
	memcpy(p->b + i + 40, opts, optlen);
	fix_ipv4_len(p, i);
	set_ip4(p, i + 12, inner_src);
	set_ip4(p, i + 16, SRC4);
	fix_tcp_csum4(p, i);
	fix_ipv4_len(p, o);
	set_ip4(p, o + 12, outer_src);
	set_ip4(p, o + 16, TEST_TUNNEL_EP);
	(void)l3;
	return i;
}

/* 6in4 from outer_src; inner IPv6 TCP from DST6 to SRC6. */
static size_t ret6(struct pkt *p, const uint8_t outer_src[4], uint8_t flags,
		   const uint8_t *opts, size_t optlen)
{
	size_t o, i;

	eth(p, ETH_IP);
	o = ipv4(p, IPPROTO_IPV6, 5, 0);
	i = ipv6(p, IPPROTO_TCP);
	tcp(p, 443, 40000, flags, 5 + (optlen + 3) / 4);
	memcpy(p->b + i + 60, opts, optlen);
	fix_ipv6_len(p, i);
	memcpy(p->b + i + 8, DST6, 16);
	memcpy(p->b + i + 24, SRC6, 16);
	fix_tcp_csum6(p, i);
	fix_ipv4_len(p, o);
	set_ip4(p, o + 12, outer_src);
	set_ip4(p, o + 16, TEST_TUNNEL_EP);
	return i;
}

/*
 * Expected forwarded reply: L2 routed to NH_MAC, ethertype of the inner
 * family, inner packet with the MSS at mss_at (offset from the inner IP
 * header; 0 = untouched) set to mss and the checksum recomputed in full.
 */
static void expected_return(struct pkt *e, const struct pkt *in, size_t l3,
			    int v6, size_t mss_at, uint16_t mss)
{
	memset(e, 0, sizeof(*e));
	put(e, in->b, l3);
	memcpy(e->b + 6, in->b, 6);
	memcpy(e->b, NH_MAC, 6);
	w16(e->b + l3 - 2, v6 ? ETH_IP6 : ETH_IP);
	put(e, in->b + l3 + 20, in->len - l3 - 20);
	if (mss_at) {
		w16(e->b + l3 + mss_at, mss);
		if (v6)
			fix_tcp_csum6(e, l3);
		else
			fix_tcp_csum4(e, l3);
	}
}

static void returned(const char *name, const struct pkt *in, size_t l3, int v6,
		     size_t mss_at, uint16_t mss)
{
	struct pkt out, want;
	char label[96];

	expect(name, in, XDP_TX, XS_V_TX_RETURN, &out);
	expected_return(&want, in, l3, v6, mss_at, mss);
	snprintf(label, sizeof(label), "%s/exact-bytes", name);
	check_bytes(label, &out, &want);
	snprintf(label, sizeof(label), "%s/tcp checksum valid", name);
	check(label, out.len >= l3 + 40 &&
		     (v6 ? tcp_csum_ok6(out.b + l3) : tcp_csum_ok4(out.b + l3)),
	      "invalid TCP checksum after rewrite");
}

static void return_path(void)
{
	static const uint8_t mss1460[] = { 2, 4, 0x05, 0xb4 };
	static const uint8_t nop_mss[] = { 1, 2, 4, 0x05, 0xb4, 1, 1, 0 };
	static const uint8_t nop3_mss[] = { 1, 1, 1, 2, 4, 0x05, 0xb4, 0 };
	static const uint8_t mss1400[] = { 2, 4, 0x05, 0x78 };
	static const uint8_t sack_mss[] = { 4, 2, 2, 4, 0x05, 0xb4, 0, 0 };
	static const uint8_t mss1440[] = { 2, 4, 0x05, 0xa0 };
	struct xs_cfg c = { 0 };
	struct pkt p;
	size_t i;

	printf("# return path\n");
	reset_state();
	add_asset4(DST4_B, 32, 9, 3, ORIGIN2, 0);
	memcpy(&c.tunnel_ep4, TEST_TUNNEL_EP, 4);
	memcpy(c.nexthop_mac, NH_MAC, 6);
	set_cfg(&c);

	/* inner IP offset 34: MSS value at inner + 20 (IP) + 20 (TCP) + 2 */
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, mss1460, 4);
	returned("return/SYN-ACK MSS 1460 clamped to 1440", &p, 14, 0, 42, 1440);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, nop_mss, 8);
	returned("return/MSS after a NOP (odd offset) clamped", &p, 14, 0, 43, 1440);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, nop3_mss, 8);
	returned("return/MSS after 3 NOPs clamped", &p, 14, 0, 45, 1440);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, mss1400, 4);
	returned("return/MSS 1400 untouched", &p, 14, 0, 0, 0);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, sack_mss, 8);
	returned("return/MSS not first: untouched (documented)", &p, 14, 0, 0, 0);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_ACK, mss1460, 4);
	returned("return/non-SYN untouched", &p, 14, 0, 0, 0);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_ACK | TCP_PSH, NULL, 0);
	returned("return/plain data segment", &p, 14, 0, 0, 0);
	p = (struct pkt){ 0 };
	ret4(&p, 100, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, mss1460, 4);
	returned("return/VLAN frame", &p, 18, 0, 42, 1440);
	p = (struct pkt){ 0 };
	ret6(&p, TEST_ORIGIN, TCP_SYN | TCP_ACK, mss1440, 4);
	returned("return/6in4 MSS 1440 clamped to 1420", &p, 14, 1, 62, 1420);
	p = (struct pkt){ 0 };
	ret4(&p, 0, ORIGIN2, DST4_B, TCP_SYN | TCP_ACK, mss1460, 4);
	returned("return/second asset's own origin", &p, 14, 0, 42, 1440);

	c.uplink_mtu = 9000;
	set_cfg(&c);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_SYN | TCP_ACK, mss1460, 4);
	returned("return/jumbo uplink: 1460 fits", &p, 14, 0, 0, 0);
	c.uplink_mtu = 0;
	set_cfg(&c);

	/* Spoofing attempts and malformed tunnels. */
	p = (struct pkt){ 0 };
	ret4(&p, 0, (const uint8_t[4]){ 192, 0, 2, 99 }, DST4, TCP_ACK, NULL, 0);
	expect("return/unknown origin dropped", &p, XDP_DROP, XS_V_DROP_RETURN, NULL);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, (const uint8_t[4]){ 198, 51, 100, 99 }, TCP_ACK, NULL, 0);
	expect("return/inner source not an asset dropped", &p, XDP_DROP, XS_V_DROP_RETURN,
	       NULL);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4_B, TCP_ACK, NULL, 0);
	expect("return/other customer's prefix dropped", &p, XDP_DROP, XS_V_DROP_RETURN, NULL);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, SRC4, TCP_ACK, NULL, 0);
	expect("return/arbitrary internet source dropped", &p, XDP_DROP, XS_V_DROP_RETURN,
	       NULL);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_ACK, NULL, 0);
	p.b[14 + 9] = IPPROTO_GRE;
	expect("return/not IPIP or 6in4 dropped", &p, XDP_DROP, XS_V_DROP_RETURN, NULL);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_ACK, NULL, 0);
	w16(p.b + 14 + 6, 0x2000); /* outer MF */
	expect("return/fragmented outer dropped", &p, XDP_DROP, XS_V_DROP_RETURN, NULL);
	p = (struct pkt){ 0 };
	i = ret4(&p, 0, TEST_ORIGIN, DST4, TCP_ACK, NULL, 0);
	w16(p.b + i + 2, 2000); /* inner length beyond the outer packet */
	expect("return/inner longer than outer dropped", &p, XDP_DROP, XS_V_DROP_RETURN, NULL);

	c.flags = XS_CFG_F_OBSERVE;
	set_cfg(&c);
	p = (struct pkt){ 0 };
	ret4(&p, 0, (const uint8_t[4]){ 192, 0, 2, 99 }, DST4, TCP_ACK, NULL, 0);
	expect("return/kill switch: invalid return to the kernel", &p, XDP_PASS,
	       XS_V_DROP_RETURN, NULL);

	c = (struct xs_cfg){ 0 }; /* no tunnel endpoint configured */
	set_cfg(&c);
	p = (struct pkt){ 0 };
	ret4(&p, 0, TEST_ORIGIN, DST4, TCP_ACK, NULL, 0);
	expect("return/endpoint not configured: no tenant", &p, XDP_DROP,
	       XS_V_DROP_NO_TENANT, NULL);
}

void run_tunnel_tests(void)
{
	lookup_and_delivery();
	mtu();
	per_asset();
	return_path();
	reset_state();
}
