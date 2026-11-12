// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Policy and SYN-cookie tests: local traffic, bogons, allow/block rules with
 * expiry, allowed services, fragments, rate limiting, observe vs mitigate,
 * and the SYN challenge with exact output bytes.
 *
 * Expected SYN-ACKs are built here independently (own checksum code); only
 * the cookie hash (ebpf/src/cookie.h) is shared with the program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <bpf/bpf.h>

#include "harness.h"
#include "../../ebpf/src/cookie.h"

#define ETH_IP 0x0800
#define ETH_IP6 0x86DD
#define ETH_VLAN 0x8100
#define NSEC 1000000000ULL

static const __u64 KEY[2] = { 0x0123456789abcdefULL, 0x0fedcba987654321ULL };

/* ---- frame builders ------------------------------------------------------ */

/* TCP to dport from 203.0.113.7:40000, with 20 bytes of options like a real
 * SYN. Returns the IP header offset. */
static size_t tcp4(struct pkt *p, uint8_t flags, uint16_t dport)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 5, 0);
	tcp(p, 40000, dport, flags, 10);
	fix_ipv4_len(p, ip);
	return ip;
}

static size_t tcp6(struct pkt *p, uint8_t flags, uint16_t dport)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_TCP);
	tcp(p, 40000, dport, flags, 10);
	fix_ipv6_len(p, ip);
	return ip;
}

static size_t udp4(struct pkt *p, uint16_t dport)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0);
	udp(p, 5353, dport, 32);
	fix_ipv4_len(p, ip);
	return ip;
}

static size_t udp6(struct pkt *p, uint16_t dport)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_UDP);
	udp(p, 5353, dport, 32);
	fix_ipv6_len(p, ip);
	return ip;
}

static size_t icmp4(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_ICMP, 5, 0);
	icmp_echo(p, 0);
	fix_ipv4_len(p, ip);
	return ip;
}

static size_t icmp6_type(struct pkt *p, uint8_t type)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_ICMPV6);
	icmp_echo(p, 1);
	p->b[ip + 40] = type;
	put(p, NULL, 16);
	fix_ipv6_len(p, ip);
	return ip;
}

static void set_src4(struct pkt *p, size_t ip, uint8_t a, uint8_t b, uint8_t c,
		     uint8_t d)
{
	uint8_t s[4] = { a, b, c, d };

	memcpy(p->b + ip + 12, s, 4);
}

static void set_src6(struct pkt *p, size_t ip, const char *addr)
{
	if (inet_pton(AF_INET6, addr, p->b + ip + 8) != 1) {
		fprintf(stderr, "bad address %s\n", addr);
		exit(2);
	}
}

static void set_dst6(struct pkt *p, size_t ip, const char *addr)
{
	if (inet_pton(AF_INET6, addr, p->b + ip + 24) != 1) {
		fprintf(stderr, "bad address %s\n", addr);
		exit(2);
	}
}

static void set_tcp_seq(struct pkt *p, size_t l4, uint32_t seq)
{
	w32(p->b + l4 + 4, seq);
}

static void cfg_with_key(struct xs_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->cookie_key[0] = KEY[0];
	c->cookie_key[1] = KEY[1];
}

/* ---- expected SYN-ACK (independent implementation) ------------------------ */

static uint32_t sum_be16(const uint8_t *b, size_t n)
{
	uint32_t s = 0;

	for (size_t i = 0; i + 1 < n; i += 2)
		s += (uint32_t)b[i] << 8 | b[i + 1];
	return s;
}

static uint16_t fin(uint32_t s)
{
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (uint16_t)~s;
}

static void expected_synack(struct pkt *e, const struct pkt *in, size_t l3,
			    int v6, uint32_t seq, uint32_t ack)
{
	const uint8_t *ip = in->b + l3;
	const uint8_t *tin = ip + (v6 ? 40 : 20);
	uint8_t *o, *t;
	uint32_t s;

	memset(e, 0, sizeof(*e));
	put(e, in->b, l3);            /* Ethernet + VLAN tags */
	memcpy(e->b, in->b + 6, 6);   /* swap MACs */
	memcpy(e->b + 6, in->b, 6);
	if (!v6) {
		o = put(e, NULL, 20);
		o[0] = 0x45;
		w16(o + 2, 40);
		w16(o + 6, 0x4000);
		o[8] = XS_SYNACK_TTL;
		o[9] = IPPROTO_TCP;
		memcpy(o + 12, ip + 16, 4);
		memcpy(o + 16, ip + 12, 4);
		w16(o + 10, fin(sum_be16(o, 20)));
	} else {
		o = put(e, NULL, 40);
		o[0] = 0x60;
		w16(o + 4, 20);
		o[6] = IPPROTO_TCP;
		o[7] = XS_SYNACK_TTL;
		memcpy(o + 8, ip + 24, 16);
		memcpy(o + 24, ip + 8, 16);
	}
	t = put(e, NULL, 20);
	memcpy(t, tin + 2, 2);
	memcpy(t + 2, tin, 2);
	w32(t + 4, seq);
	w32(t + 8, ack);
	t[12] = 5 << 4;
	t[13] = 0x12;
	w16(t + 14, XS_SYNACK_WINDOW);
	s = sum_be16(t, 20) + IPPROTO_TCP + 20 +
	    (v6 ? sum_be16(o + 8, 32) : sum_be16(o + 12, 8));
	w16(t + 16, fin(s));
}

static uint64_t cookie_hash(const struct pkt *in, size_t l3, int v6, uint32_t slot)
{
	const uint8_t *ip = in->b + l3;
	const uint8_t *t = ip + (v6 ? 40 : 20);
	__be16 sp, dp;

	memcpy(&sp, t, 2);
	memcpy(&dp, t + 2, 2);
	if (!v6) {
		__be32 s, d;

		memcpy(&s, ip + 12, 4);
		memcpy(&d, ip + 16, 4);
		return xs_cookie_hash4(KEY, s, d, sp, dp, slot);
	}
	return xs_cookie_hash6(KEY, ip + 8, ip + 24, sp, dp, slot);
}

static uint32_t rd32(const uint8_t *b)
{
	return (uint32_t)b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
}

/*
 * Sends SYN `in`, expects a challenge, and compares the output frame with the
 * independently built SYN-ACK. Returns the cookie (ack number) sent.
 */
static uint32_t expect_challenge(const char *name, const struct pkt *in,
				 size_t l3, int v6)
{
	char label[96];

	for (int attempt = 0; attempt < 3; attempt++) {
		uint32_t slot = xs_cookie_slot(boot_ns());
		struct pkt out, want;
		uint64_t h;
		uint32_t isn = rd32(in->b + l3 + (v6 ? 40 : 20) + 4), ack;

		expect(name, in, XDP_TX, XS_V_TX_SYN_CHALLENGE, &out);
		if (xs_cookie_slot(boot_ns()) != slot)
			continue; /* crossed a slot boundary mid-test: retry */
		h = cookie_hash(in, l3, v6, slot);
		ack = xs_challenge_ack(h, isn);
		expected_synack(&want, in, l3, v6, xs_challenge_seq(h), ack);

		snprintf(label, sizeof(label), "%s/exact-bytes (%zu)", name, want.len);
		if (out.len != want.len) {
			char why[64];

			snprintf(why, sizeof(why), "length %zu, want %zu", out.len, want.len);
			check(label, 0, why);
		} else {
			size_t i = 0;
			char why[64];

			while (i < want.len && out.b[i] == want.b[i])
				i++;
			snprintf(why, sizeof(why), "first difference at byte %zu", i);
			check(label, i == want.len, why);
		}
		return ack;
	}
	check(name, 0, "cookie slot changed on every attempt");
	return 0;
}

static int verified_until(const uint8_t addr16[16], uint64_t *exp)
{
	struct xs_addr_key k = { .tenant = TEST_TENANT };

	memcpy(k.addr, addr16, 16);
	return bpf_map_lookup_elem(fd.verified, &k, exp) == 0;
}

static void v4_mapped(uint8_t out[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	memset(out, 0, 16);
	out[10] = out[11] = 0xff;
	out[12] = a;
	out[13] = b;
	out[14] = c;
	out[15] = d;
}

/* ---- suites ---------------------------------------------------------------- */

static void local_and_bogons(void)
{
	struct xs_cfg c = { 0 };
	struct pkt p;
	size_t ip;
	uint8_t net[4] = { 203, 0, 113, 0 };

	printf("# local traffic and bogons\n");
	reset_state();
	set_policy(XS_P_MITIGATE | XS_P_SERVICES, 0, 0); /* no services: drop all */
	add_rule4(fd.block, 0, net, 24, boot_ns() + 60 * NSEC);
	memcpy(&c.pop_ip4, DST4, 4);
	memcpy(c.pop_ip6, DST6, 16);
	set_cfg(&c);

	p = (struct pkt){ 0 };
	tcp4(&p, TCP_SYN, 22);
	expect("local/ipv4 to pop ip beats block+services", &p, XDP_PASS, XS_V_PASS_LOCAL, NULL);
	p = (struct pkt){ 0 };
	tcp6(&p, TCP_SYN, 179);
	expect("local/ipv6 to pop ip", &p, XDP_PASS, XS_V_PASS_LOCAL, NULL);

	c = (struct xs_cfg){ 0 };
	set_cfg(&c);
	p = (struct pkt){ 0 };
	ip = icmp6_type(&p, 135);
	set_src6(&p, ip, "fe80::1");
	set_dst6(&p, ip, "ff02::1:ff00:10");
	expect("local/ipv6 neighbour solicitation", &p, XDP_PASS, XS_V_PASS_LOCAL, NULL);
	p = (struct pkt){ 0 };
	ip = icmp6_type(&p, 136);
	set_src6(&p, ip, "fe80::1");
	set_dst6(&p, ip, "fe80::2");
	expect("local/ipv6 neighbour advertisement", &p, XDP_PASS, XS_V_PASS_LOCAL, NULL);
	p = (struct pkt){ 0 };
	ip = icmp6_type(&p, 128);
	set_src6(&p, ip, "fe80::1");
	set_dst6(&p, ip, "ff02::1");
	expect("local/ipv6 echo from link-local is a bogon", &p, XDP_DROP, XS_V_DROP_BOGON, NULL);
	p = (struct pkt){ 0 };
	ip = icmp6_type(&p, 135);
	set_src6(&p, ip, "2001:db8:ffff::7");
	expect("local/ND to a global address is not local", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);

	/* Bogon sources are dropped regardless of policy (even observe). */
	reset_state();
	{
		static const uint8_t bog4[][4] = {
			{ 0, 1, 2, 3 }, { 10, 1, 2, 3 }, { 100, 64, 0, 1 },
			{ 100, 127, 255, 254 }, { 127, 0, 0, 1 }, { 169, 254, 1, 1 },
			{ 172, 16, 0, 1 }, { 172, 31, 255, 254 }, { 192, 168, 1, 1 },
			{ 224, 0, 0, 5 }, { 239, 255, 255, 250 }, { 240, 0, 0, 1 },
			{ 255, 255, 255, 255 },
		};
		static const uint8_t ok4[][4] = {
			{ 1, 1, 1, 1 }, { 11, 0, 0, 1 }, { 100, 63, 255, 255 },
			{ 100, 128, 0, 1 }, { 172, 15, 255, 255 }, { 172, 32, 0, 1 },
			{ 192, 169, 0, 1 }, { 223, 255, 255, 255 }, { 203, 0, 113, 7 },
		};
		char name[64];

		for (size_t i = 0; i < sizeof(bog4) / 4; i++) {
			p = (struct pkt){ 0 };
			ip = udp4(&p, 53);
			set_src4(&p, ip, bog4[i][0], bog4[i][1], bog4[i][2], bog4[i][3]);
			snprintf(name, sizeof(name), "bogon/%u.%u.%u.%u", bog4[i][0],
				 bog4[i][1], bog4[i][2], bog4[i][3]);
			expect(name, &p, XDP_DROP, XS_V_DROP_BOGON, NULL);
		}
		for (size_t i = 0; i < sizeof(ok4) / 4; i++) {
			p = (struct pkt){ 0 };
			ip = udp4(&p, 53);
			set_src4(&p, ip, ok4[i][0], ok4[i][1], ok4[i][2], ok4[i][3]);
			snprintf(name, sizeof(name), "not-bogon/%u.%u.%u.%u", ok4[i][0],
				 ok4[i][1], ok4[i][2], ok4[i][3]);
			expect(name, &p, XDP_TX, XS_V_PASS, NULL);
		}
	}
	{
		static const char *bog6[] = { "::", "::1", "::ffff:1.2.3.4", "fc00::1",
					      "fdff::1", "fe80::1", "febf::1", "ff02::1",
					      "ff0e::1" };
		static const char *ok6[] = { "2001:db8:ffff::7", "::2", "fec0::1",
					     "2001:db8:100::1", "64:ff9b::1.2.3.4" };
		char name[64];

		for (size_t i = 0; i < sizeof(bog6) / sizeof(bog6[0]); i++) {
			p = (struct pkt){ 0 };
			ip = udp6(&p, 53);
			set_src6(&p, ip, bog6[i]);
			snprintf(name, sizeof(name), "bogon/%s", bog6[i]);
			expect(name, &p, XDP_DROP, XS_V_DROP_BOGON, NULL);
		}
		for (size_t i = 0; i < sizeof(ok6) / sizeof(ok6[0]); i++) {
			p = (struct pkt){ 0 };
			ip = udp6(&p, 53);
			set_src6(&p, ip, ok6[i]);
			snprintf(name, sizeof(name), "not-bogon/%s", ok6[i]);
			expect(name, &p, XDP_TX, XS_V_PASS, NULL);
		}
	}
	c.flags = XS_CFG_F_OBSERVE;
	set_cfg(&c);
	p = (struct pkt){ 0 };
	ip = udp4(&p, 53);
	set_src4(&p, ip, 10, 0, 0, 1);
	expect("bogon/global observe passes", &p, XDP_TX, XS_V_DROP_BOGON, NULL);
}

static void rules(void)
{
	struct pkt p = { 0 };
	uint64_t now = boot_ns();
	uint8_t net24[4] = { 203, 0, 113, 0 }, host[4] = { 203, 0, 113, 7 };
	uint8_t net6[16];

	printf("# allow and block lists\n");
	memcpy(net6, SRC6, 16);
	memset(net6 + 6, 0, 10); /* 2001:db8:ffff::/48 */
	udp4(&p, 53);

	reset_state();
	set_policy(XS_P_MITIGATE, 0, 0);
	add_rule4(fd.block, 0, net24, 24, now + 60 * NSEC);
	expect("block/active /24", &p, XDP_DROP, XS_V_DROP_BLOCK, NULL);
	set_policy(0, 0, 0);
	expect("block/observe counts but passes", &p, XDP_TX, XS_V_DROP_BLOCK, NULL);
	set_policy(XS_P_MITIGATE, 0, 0);

	add_rule4(fd.block, 0, net24, 24, now - 1);
	expect("block/expired is ignored", &p, XDP_TX, XS_V_PASS, NULL);
	add_rule4(fd.block, 0, net24, 24, 0);
	expect("block/without expiry is ignored", &p, XDP_TX, XS_V_PASS, NULL);
	add_rule4(fd.block, 5, net24, 24, now + 60 * NSEC);
	expect("block/other tenant does not match", &p, XDP_TX, XS_V_PASS, NULL);
	add_rule4(fd.block, TEST_TENANT, net24, 24, now + 60 * NSEC);
	expect("block/own tenant matches", &p, XDP_DROP, XS_V_DROP_BLOCK, NULL);
	add_rule4(fd.block, TEST_TENANT, net24, 24, now - 1);

	add_rule4(fd.block, 0, net24, 24, now + 60 * NSEC);
	add_rule4(fd.allow, 0, host, 32, 0);
	expect("allow/permanent beats block", &p, XDP_TX, XS_V_PASS_ALLOW, NULL);
	add_rule4(fd.allow, 0, host, 32, now - 1);
	expect("allow/expired no longer wins", &p, XDP_DROP, XS_V_DROP_BLOCK, NULL);
	add_rule4(fd.allow, 0, host, 32, now + 60 * NSEC);
	expect("allow/with ttl beats block", &p, XDP_TX, XS_V_PASS_ALLOW, NULL);

	p = (struct pkt){ 0 };
	udp6(&p, 53);
	add_rule6(fd.block6, 0, net6, 48, now + 60 * NSEC);
	expect("block/ipv6 /48", &p, XDP_DROP, XS_V_DROP_BLOCK, NULL);
	add_rule6(fd.allow6, 0, SRC6, 128, 0);
	expect("allow/ipv6 /128 beats block", &p, XDP_TX, XS_V_PASS_ALLOW, NULL);

	/* Allowlisted sources skip services and rate limits. */
	reset_state();
	set_policy(XS_P_MITIGATE | XS_P_SERVICES, 1, 1);
	p = (struct pkt){ 0 };
	udp4(&p, 9999);
	expect("allow/without rule: service dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	add_rule4(fd.allow, 0, host, 32, 0);
	expect("allow/skips services #1", &p, XDP_TX, XS_V_PASS_ALLOW, NULL);
	expect("allow/skips rate limit #2", &p, XDP_TX, XS_V_PASS_ALLOW, NULL);
}

static void services_and_fragments(void)
{
	struct pkt p;
	size_t ip;

	printf("# allowed services and fragments\n");
	reset_state();
	set_policy(XS_P_MITIGATE | XS_P_SERVICES, 0, 0);
	add_service(IPPROTO_TCP, 443);

	p = (struct pkt){ 0 };
	tcp4(&p, TCP_SYN, 443);
	expect("services/tcp 443 allowed", &p, XDP_TX, XS_V_PASS, NULL);
	p = (struct pkt){ 0 };
	tcp6(&p, TCP_SYN, 443);
	expect("services/tcp 443 allowed (ipv6)", &p, XDP_TX, XS_V_PASS, NULL);
	p = (struct pkt){ 0 };
	tcp4(&p, TCP_SYN, 80);
	expect("services/tcp 80 dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	p = (struct pkt){ 0 };
	udp4(&p, 53);
	expect("services/udp 53 dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	add_service(IPPROTO_UDP, 0);
	expect("services/udp port 0 allows all ports", &p, XDP_TX, XS_V_PASS, NULL);
	p = (struct pkt){ 0 };
	icmp4(&p);
	expect("services/icmp dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	add_service(IPPROTO_ICMP, 0);
	expect("services/icmp allowed", &p, XDP_TX, XS_V_PASS, NULL);
	p = (struct pkt){ 0 };
	icmp6_type(&p, 128);
	expect("services/icmpv6 dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);

	/* ICMP errors bypass services (path MTU discovery must keep working). */
	map_clear(fd.services);
	p = (struct pkt){ 0 };
	ip = icmp4(&p);
	p.b[ip + 20] = 3; /* destination unreachable */
	p.b[ip + 21] = 4; /* fragmentation needed */
	expect("services/icmp frag-needed passes", &p, XDP_TX, XS_V_PASS, NULL);
	p.b[ip + 20] = 11;
	expect("services/icmp time-exceeded passes", &p, XDP_TX, XS_V_PASS, NULL);
	p.b[ip + 20] = 5;
	expect("services/icmp redirect dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	p = (struct pkt){ 0 };
	icmp6_type(&p, 2);
	expect("services/icmpv6 packet-too-big passes", &p, XDP_TX, XS_V_PASS, NULL);
	p = (struct pkt){ 0 };
	icmp6_type(&p, 129);
	expect("services/icmpv6 echo reply dropped", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	{
		uint8_t host[4] = { 203, 0, 113, 7 };

		p = (struct pkt){ 0 };
		ip = icmp4(&p);
		p.b[ip + 20] = 3;
		add_rule4(fd.block, 0, host, 32, boot_ns() + 60 * NSEC);
		expect("services/icmp error from blocked source dropped", &p, XDP_DROP,
		       XS_V_DROP_BLOCK, NULL);
	}

	reset_state();
	set_policy(XS_P_MITIGATE, 0, 0);
	p = (struct pkt){ 0 };
	tcp4(&p, TCP_SYN, 80);
	expect("services/not enforced", &p, XDP_TX, XS_V_PASS, NULL);

	/* Non-first fragment (offset 800 bytes). */
	p = (struct pkt){ 0 };
	eth(&p, ETH_IP);
	ip = ipv4(&p, IPPROTO_UDP, 5, 100);
	put(&p, NULL, 64);
	fix_ipv4_len(&p, ip);
	expect("fragments/dropped by default", &p, XDP_DROP, XS_V_DROP_FRAGMENT, NULL);
	set_policy(0, 0, 0);
	expect("fragments/observe passes", &p, XDP_TX, XS_V_DROP_FRAGMENT, NULL);
	set_policy(XS_P_MITIGATE | XS_P_ALLOW_FRAG | XS_P_SERVICES, 0, 0);
	expect("fragments/allowed skip services", &p, XDP_TX, XS_V_FRAGMENT, NULL);

	/* A first fragment carries ports, so services apply. */
	reset_state();
	set_policy(XS_P_MITIGATE | XS_P_ALLOW_FRAG | XS_P_SERVICES, 0, 0);
	p = (struct pkt){ 0 };
	eth(&p, ETH_IP);
	ip = ipv4(&p, IPPROTO_UDP, 5, 0x2000);
	udp(&p, 1000, 53, 64);
	fix_ipv4_len(&p, ip);
	expect("fragments/first fragment checked against services", &p, XDP_DROP,
	       XS_V_DROP_SERVICE, NULL);
}

static void rate_limit(void)
{
	struct pkt p = { 0 };
	struct xs_addr_key k = { .tenant = TEST_TENANT };
	struct xs_rl b;
	size_t ip;

	printf("# per-source token bucket\n");
	reset_state();
	set_policy(XS_P_MITIGATE, 10, 3);
	udp4(&p, 53);
	expect("ratelimit/burst 1 of 3", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/burst 2 of 3", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/burst 3 of 3", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/4th dropped", &p, XDP_DROP, XS_V_DROP_RATELIMIT, NULL);
	expect("ratelimit/5th dropped", &p, XDP_DROP, XS_V_DROP_RATELIMIT, NULL);

	/* Pretend 150 ms passed: 10 pps refills 1.5 tokens. */
	v4_mapped(k.addr, 203, 0, 113, 7);
	if (bpf_map_lookup_elem(fd.rl, &k, &b))
		check("ratelimit/bucket exists", 0, "no xs_rl entry for 203.0.113.7");
	b.last_ns -= 150 * 1000000ULL;
	bpf_map_update_elem(fd.rl, &k, &b, BPF_EXIST);
	expect("ratelimit/refilled one token", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/half a token is not enough", &p, XDP_DROP, XS_V_DROP_RATELIMIT, NULL);

	/* Long idle: refill caps at the burst. */
	bpf_map_lookup_elem(fd.rl, &k, &b);
	b.last_ns -= 10 * NSEC; /* full refill needs 0.3 s; boot clock may be young */
	bpf_map_update_elem(fd.rl, &k, &b, BPF_EXIST);
	expect("ratelimit/after idle 1 of 3", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/after idle 2 of 3", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/after idle 3 of 3", &p, XDP_TX, XS_V_PASS, NULL);
	expect("ratelimit/after idle capped at burst", &p, XDP_DROP, XS_V_DROP_RATELIMIT, NULL);

	p = (struct pkt){ 0 };
	ip = udp4(&p, 53);
	set_src4(&p, ip, 203, 0, 113, 8);
	expect("ratelimit/other source has its own bucket", &p, XDP_TX, XS_V_PASS, NULL);

	set_policy(0, 10, 3);
	p = (struct pkt){ 0 };
	udp4(&p, 53);
	expect("ratelimit/observe counts but passes", &p, XDP_TX, XS_V_DROP_RATELIMIT, NULL);

	/* IPv6 sources share a bucket per /64. burst 0 = pps. */
	reset_state();
	set_policy(XS_P_MITIGATE, 2, 0);
	p = (struct pkt){ 0 };
	ip = udp6(&p, 53);
	set_src6(&p, ip, "2001:db8:ffff::7");
	expect("ratelimit/ipv6 /64 #1", &p, XDP_TX, XS_V_PASS, NULL);
	set_src6(&p, ip, "2001:db8:ffff::8");
	expect("ratelimit/ipv6 /64 #2 (other host)", &p, XDP_TX, XS_V_PASS, NULL);
	set_src6(&p, ip, "2001:db8:ffff::9");
	expect("ratelimit/ipv6 /64 shared bucket empty", &p, XDP_DROP, XS_V_DROP_RATELIMIT, NULL);
	set_src6(&p, ip, "2001:db8:ffff:1::7");
	expect("ratelimit/ipv6 other /64", &p, XDP_TX, XS_V_PASS, NULL);
}

static void syn_cookies(void)
{
	struct xs_cfg c;
	struct pkt syn, rst, ack, out;
	uint8_t a7[16];
	uint64_t exp, now;
	uint32_t cookie;
	size_t ip;

	printf("# SYN-cookie source verification\n");
	reset_state();
	cfg_with_key(&c);
	set_cfg(&c);
	set_policy(XS_P_MITIGATE | XS_P_SYNCOOKIE | XS_P_SERVICES, 0, 0);
	add_service(IPPROTO_TCP, 80);
	v4_mapped(a7, 203, 0, 113, 7);

	syn = (struct pkt){ 0 };
	tcp4(&syn, TCP_SYN, 80);
	cookie = expect_challenge("syncookie/ipv4 SYN challenged", &syn, 14, 0);
	check("syncookie/challenge does not verify", !verified_until(a7, &exp),
	      "source verified before answering");

	ack = (struct pkt){ 0 };
	tcp4(&ack, TCP_ACK, 80);
	expect("syncookie/ACK from unverified dropped", &ack, XDP_DROP,
	       XS_V_DROP_UNVERIFIED, NULL);

	rst = (struct pkt){ 0 };
	tcp4(&rst, TCP_RST, 80);
	set_tcp_seq(&rst, 34, cookie + 2); /* never equals cookie or cookie^1 */
	expect("syncookie/RST with wrong cookie dropped", &rst, XDP_DROP,
	       XS_V_DROP_UNVERIFIED, NULL);
	set_tcp_seq(&rst, 34, cookie);
	now = boot_ns();
	expect("syncookie/RST with cookie verifies source", &rst, XDP_DROP,
	       XS_V_SYN_VERIFIED, NULL);
	check("syncookie/verified entry ~300s",
	      verified_until(a7, &exp) && exp > now + 299 * NSEC &&
		      exp < boot_ns() + 301 * NSEC,
	      "missing or wrong expiry");

	expect("syncookie/SYN from verified source passes", &syn, XDP_TX, XS_V_PASS, NULL);
	expect("syncookie/ACK from verified source passes", &ack, XDP_TX, XS_V_PASS, NULL);

	/* Verification expires. */
	{
		struct xs_addr_key k = { .tenant = TEST_TENANT };
		uint64_t past = boot_ns() - 1;

		memcpy(k.addr, a7, 16);
		bpf_map_update_elem(fd.verified, &k, &past, BPF_EXIST);
		expect("syncookie/expired verification: ACK dropped", &ack, XDP_DROP,
		       XS_V_DROP_UNVERIFIED, NULL);
		expect_challenge("syncookie/expired verification: SYN challenged", &syn, 14, 0);

		/* Refresh: an entry close to expiry is extended by traffic. */
		past = boot_ns() + 10 * NSEC;
		bpf_map_update_elem(fd.verified, &k, &past, BPF_ANY);
		expect("syncookie/verified traffic refreshes", &ack, XDP_TX, XS_V_PASS, NULL);
		check("syncookie/refreshed to ~300s",
		      verified_until(a7, &exp) && exp > boot_ns() + 290 * NSEC,
		      "entry not refreshed");
	}

	/* The previous time slot is accepted, older ones are not. */
	{
		uint32_t slot = xs_cookie_slot(boot_ns());
		uint8_t a9[16];
		struct pkt r9 = { 0 };

		ip = tcp4(&r9, TCP_RST, 80);
		set_src4(&r9, ip, 203, 0, 113, 9);
		v4_mapped(a9, 203, 0, 113, 9);
		set_tcp_seq(&r9, 34, (uint32_t)cookie_hash(&r9, 14, 0, slot - 2));
		expect("syncookie/cookie two slots old rejected", &r9, XDP_DROP,
		       XS_V_DROP_UNVERIFIED, NULL);
		set_tcp_seq(&r9, 34, (uint32_t)cookie_hash(&r9, 14, 0, slot - 1) ^ 1);
		expect("syncookie/previous slot (low bit flipped) accepted", &r9,
		       XDP_DROP, XS_V_SYN_VERIFIED, NULL);
		check("syncookie/203.0.113.9 verified", verified_until(a9, &exp),
		      "not in xs_verified");
	}

	/* What is never challenged. */
	syn = (struct pkt){ 0 };
	eth(&syn, ETH_IP);
	ip = ipv4(&syn, IPPROTO_TCP, 6, 0); /* IP options */
	tcp(&syn, 40001, 80, TCP_SYN, 5);
	fix_ipv4_len(&syn, ip);
	set_src4(&syn, ip, 203, 0, 113, 20);
	expect("syncookie/SYN with IP options dropped", &syn, XDP_DROP,
	       XS_V_DROP_UNVERIFIED, NULL);
	syn = (struct pkt){ 0 };
	ip = tcp4(&syn, TCP_SYN | TCP_ACK, 80);
	set_src4(&syn, ip, 203, 0, 113, 21);
	expect("syncookie/SYN-ACK from unverified dropped", &syn, XDP_DROP,
	       XS_V_DROP_UNVERIFIED, NULL);
	syn = (struct pkt){ 0 };
	eth(&syn, ETH_IP6);
	ip = ipv6(&syn, 0);
	ext6(&syn, IPPROTO_TCP, 0);
	tcp(&syn, 40000, 80, TCP_SYN, 5);
	fix_ipv6_len(&syn, ip);
	expect("syncookie/ipv6 SYN with ext header dropped", &syn, XDP_DROP,
	       XS_V_DROP_UNVERIFIED, NULL);
	add_service(IPPROTO_UDP, 0);
	syn = (struct pkt){ 0 };
	ip = udp4(&syn, 53);
	set_src4(&syn, ip, 203, 0, 113, 22);
	expect("syncookie/UDP unaffected", &syn, XDP_TX, XS_V_PASS, NULL);

	/* IPv6 and VLAN challenges, exact bytes. */
	syn = (struct pkt){ 0 };
	tcp6(&syn, TCP_SYN, 80);
	expect_challenge("syncookie/ipv6 SYN challenged", &syn, 14, 1);
	syn = (struct pkt){ 0 };
	eth(&syn, ETH_VLAN);
	vlan(&syn, 100, ETH_IP);
	ip = ipv4(&syn, IPPROTO_TCP, 5, 0);
	tcp(&syn, 40002, 80, TCP_SYN, 10);
	fix_ipv4_len(&syn, ip);
	put(&syn, NULL, 6); /* trailing padding must be trimmed too */
	set_src4(&syn, ip, 203, 0, 113, 30);
	expect_challenge("syncookie/VLAN SYN challenged", &syn, 18, 0);

	/* Observe, kill switch, missing key: never rewrite. */
	syn = (struct pkt){ 0 };
	ip = tcp4(&syn, TCP_SYN, 80);
	set_src4(&syn, ip, 203, 0, 113, 40);
	set_policy(XS_P_SYNCOOKIE | XS_P_SERVICES, 0, 0);
	expect("syncookie/observe: counted, passed", &syn, XDP_TX,
	       XS_V_TX_SYN_CHALLENGE, &out);
	check("syncookie/observe: delivered unchanged through the tunnel",
	      out.len == syn.len + 20 && !memcmp(out.b + 34, syn.b + 14, syn.len - 14),
	      "inner frame modified");
	set_policy(XS_P_MITIGATE | XS_P_SYNCOOKIE | XS_P_SERVICES, 0, 0);
	c.flags = XS_CFG_F_OBSERVE;
	set_cfg(&c);
	expect("syncookie/kill switch: counted, passed", &syn, XDP_TX,
	       XS_V_TX_SYN_CHALLENGE, &out);
	check("syncookie/kill switch: delivered unchanged through the tunnel",
	      out.len == syn.len + 20 && !memcmp(out.b + 34, syn.b + 14, syn.len - 14),
	      "inner frame modified");
	c = (struct xs_cfg){ 0 };
	set_cfg(&c); /* PoP IP only: no SYN-cookie key */
	expect("syncookie/no key: fail open", &syn, XDP_TX, XS_V_PASS, NULL);
}

static void siphash_vectors(void)
{
	/* Reference vectors (SipHash-2-4 paper, key 00..0f, message 00..n-1). */
	__u64 m = 0x0706050403020100ULL;

	printf("# siphash reference vectors\n");
	check("siphash/empty message",
	      xs_siphash24(0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, &m, 0) ==
		      0x726fdb47dd0e0e31ULL,
	      "mismatch");
	check("siphash/8-byte message",
	      xs_siphash24(0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, &m, 1) ==
		      0x93f5f5799a932462ULL,
	      "mismatch");
}

void run_policy_tests(void)
{
	siphash_vectors();
	local_and_bogons();
	rules();
	services_and_fragments();
	rate_limit();
	syn_cookies();
	reset_state();
}
