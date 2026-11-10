/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Phase 1 parser cases: crafted frame -> expected XDP action and verdict. */
#ifndef XS_CASES_H
#define XS_CASES_H

#include <linux/bpf.h>
#include <netinet/in.h>

#include "../common/pktbuild.h"
#include "../../ebpf/include/abi.h"

#define ETH_IP 0x0800
#define ETH_IP6 0x86DD
#define ETH_ARP 0x0806
#define ETH_VLAN 0x8100
#define ETH_QINQ 0x88A8
#define NH_HOP 0
#define NH_ROUTING 43
#define NH_FRAG 44
#define NH_NONE 59
#define NH_DEST 60

struct xs_case {
	const char *name;
	void (*build)(struct pkt *p);
	int action;  /* XDP_PASS / XDP_DROP */
	int verdict; /* enum xs_verdict */
};

/* ---- well-formed IPv4 ---------------------------------------------- */

static void c_ipv4_tcp_syn(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 5, 0);
	tcp(p, 40000, 443, TCP_SYN, 5);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_tcp_options(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 5, 0);
	tcp(p, 40000, 443, TCP_SYN, 10); /* 20 bytes of TCP options */
	fix_ipv4_len(p, ip);
}

static void c_ipv4_udp(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0);
	udp(p, 5353, 53, 32);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_icmp(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_ICMP, 5, 0);
	icmp_echo(p, 0);
	put(p, NULL, 56);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_ip_options(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 15, 0); /* 40 bytes of IP options */
	tcp(p, 40000, 80, TCP_ACK, 5);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_eth_padding(struct pkt *p)
{
	/* 42-byte IP packet padded to the 60-byte Ethernet minimum. */
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0);
	udp(p, 1000, 53, 0);
	fix_ipv4_len(p, ip);
	put(p, NULL, 60 - p->len);
}

static void c_ipv4_gre(struct pkt *p)
{
	/* Protocol without ports: parsed at L3 only. */
	eth(p, ETH_IP);
	size_t ip = ipv4(p, 47, 5, 0);
	put(p, NULL, 24);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_frag_first(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0x2000); /* MF, offset 0 */
	udp(p, 1000, 53, 64);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_frag_later(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 100); /* offset 800 bytes */
	put(p, NULL, 64);
	fix_ipv4_len(p, ip);
}

/* ---- well-formed IPv6 ---------------------------------------------- */

static void c_ipv6_tcp(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_TCP);
	tcp(p, 40000, 443, TCP_SYN, 5);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_udp(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_UDP);
	udp(p, 5353, 53, 32);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_icmpv6(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_ICMPV6);
	icmp_echo(p, 1);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_no_next(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, NH_NONE);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_ext_chain_max(struct pkt *p)
{
	/* Exactly XS_MAX_IPV6_EXT_HDRS (4) headers, then TCP. */
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, NH_HOP);
	ext6(p, NH_DEST, 0);
	ext6(p, NH_ROUTING, 1);
	ext6(p, NH_DEST, 0);
	ext6(p, IPPROTO_TCP, 0);
	tcp(p, 40000, 443, TCP_SYN, 5);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_frag_first(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, NH_FRAG);
	frag6(p, IPPROTO_UDP, 0, 1);
	udp(p, 1000, 53, 64);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_frag_later(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, NH_HOP);
	ext6(p, NH_FRAG, 0);
	frag6(p, IPPROTO_UDP, 185, 0);
	put(p, NULL, 64);
	fix_ipv6_len(p, ip);
}

/* ---- VLAN ------------------------------------------------------------ */

static void c_vlan_one(struct pkt *p)
{
	eth(p, ETH_VLAN);
	vlan(p, 100, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0);
	udp(p, 1000, 53, 16);
	fix_ipv4_len(p, ip);
}

static void c_vlan_qinq(struct pkt *p)
{
	eth(p, ETH_QINQ);
	vlan(p, 200, ETH_VLAN);
	vlan(p, 100, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_TCP);
	tcp(p, 40000, 443, TCP_SYN, 5);
	fix_ipv6_len(p, ip);
}

/* ---- non-IP ---------------------------------------------------------- */

static void c_arp(struct pkt *p)
{
	eth(p, ETH_ARP);
	put(p, NULL, 28);
}

static void c_unknown_ethertype(struct pkt *p)
{
	eth(p, 0x88B5); /* IEEE local experimental */
	put(p, NULL, 46);
}

static void c_vlan_arp(struct pkt *p)
{
	eth(p, ETH_VLAN);
	vlan(p, 100, ETH_ARP);
	put(p, NULL, 28);
}

/* ---- malformed ------------------------------------------------------- */

static void c_vlan_three_tags(struct pkt *p)
{
	eth(p, ETH_QINQ);
	vlan(p, 1, ETH_VLAN);
	vlan(p, 2, ETH_VLAN);
	vlan(p, 3, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 5, 0);
	udp(p, 1000, 53, 16);
	fix_ipv4_len(p, ip);
}

static void c_vlan_truncated(struct pkt *p)
{
	eth(p, ETH_VLAN);
	put(p, NULL, 2); /* half a tag */
}

static void c_ipv4_truncated(struct pkt *p)
{
	eth(p, ETH_IP);
	put(p, NULL, 10)[0] = 0x45;
}

static void c_ipv4_ihl_too_small(struct pkt *p)
{
	c_ipv4_udp(p);
	p->b[14] = 0x44; /* ihl 4 */
}

static void c_ipv4_bad_version(struct pkt *p)
{
	c_ipv4_udp(p);
	p->b[14] = 0x65;
}

static void c_ipv4_ihl_beyond_frame(struct pkt *p)
{
	/* ihl 15 (60 bytes) but only 24 bytes of IP header present. */
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_UDP, 6, 0);
	fix_ipv4_len(p, ip);
	p->b[ip] = 0x4f;
	w16(p->b + ip + 2, 60);
}

static void c_ipv4_totlen_beyond_frame(struct pkt *p)
{
	c_ipv4_udp(p);
	w16(p->b + 14 + 2, 1500);
}

static void c_ipv4_totlen_below_ihl(struct pkt *p)
{
	c_ipv4_udp(p);
	w16(p->b + 14 + 2, 12);
}

static void c_ipv4_udp_outside_totlen(struct pkt *p)
{
	/* UDP bytes exist in the frame, but tot_len stops after 4 of them. */
	c_ipv4_udp(p);
	w16(p->b + 14 + 2, 24);
}

static void c_ipv4_tcp_truncated(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 5, 0);
	put(p, NULL, 10);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_tcp_doff_too_small(struct pkt *p)
{
	c_ipv4_tcp_syn(p);
	p->b[14 + 20 + 12] = 4 << 4;
}

static void c_ipv4_tcp_doff_beyond(struct pkt *p)
{
	c_ipv4_tcp_syn(p);
	p->b[14 + 20 + 12] = 15 << 4; /* claims 60 bytes, frame has 20 */
}

static void c_ipv4_tiny_first_fragment(struct pkt *p)
{
	/* Classic tiny-fragment attack: first fragment with half a TCP header. */
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_TCP, 5, 0x2000);
	put(p, NULL, 8);
	fix_ipv4_len(p, ip);
}

static void c_ipv4_icmp_truncated(struct pkt *p)
{
	eth(p, ETH_IP);
	size_t ip = ipv4(p, IPPROTO_ICMP, 5, 0);
	put(p, NULL, 4);
	fix_ipv4_len(p, ip);
}

static void c_ipv6_truncated(struct pkt *p)
{
	eth(p, ETH_IP6);
	put(p, NULL, 20)[0] = 0x60;
}

static void c_ipv6_bad_version(struct pkt *p)
{
	c_ipv6_udp(p);
	p->b[14] = 0x40;
}

static void c_ipv6_payload_beyond_frame(struct pkt *p)
{
	c_ipv6_udp(p);
	w16(p->b + 14 + 4, 1000);
}

static void c_ipv6_ext_chain_too_long(struct pkt *p)
{
	/* XS_MAX_IPV6_EXT_HDRS + 1 headers. */
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, NH_HOP);
	ext6(p, NH_DEST, 0);
	ext6(p, NH_DEST, 0);
	ext6(p, NH_DEST, 0);
	ext6(p, NH_DEST, 0);
	ext6(p, IPPROTO_TCP, 0);
	tcp(p, 40000, 443, TCP_SYN, 5);
	fix_ipv6_len(p, ip);
}

static void c_ipv6_ext_truncated(struct pkt *p)
{
	/* HOP header claims 16 bytes; only 8 are in the frame. */
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, NH_HOP);
	ext6(p, IPPROTO_TCP, 0);
	fix_ipv6_len(p, ip);
	p->b[ip + 40 + 1] = 1;
}

static void c_ipv6_ext_beyond_payload(struct pkt *p)
{
	/* The frame has the bytes, but payload_len ends inside the header. */
	c_ipv6_ext_chain_max(p);
	w16(p->b + 14 + 4, 12);
}

static void c_ipv6_udp_truncated(struct pkt *p)
{
	eth(p, ETH_IP6);
	size_t ip = ipv6(p, IPPROTO_UDP);
	put(p, NULL, 4);
	fix_ipv6_len(p, ip);
}

#define PASS(n) { #n, c_##n, XDP_PASS, XS_V_PASS }
#define NONIP(n) { #n, c_##n, XDP_PASS, XS_V_PASS_NON_IP }
#define FRAG(n) { #n, c_##n, XDP_PASS, XS_V_FRAGMENT }
#define BAD(n) { #n, c_##n, XDP_DROP, XS_V_DROP_MALFORMED }

static const struct xs_case xs_cases[] = {
	PASS(ipv4_tcp_syn),
	PASS(ipv4_tcp_options),
	PASS(ipv4_udp),
	PASS(ipv4_icmp),
	PASS(ipv4_ip_options),
	PASS(ipv4_eth_padding),
	PASS(ipv4_gre),
	PASS(ipv4_frag_first),
	FRAG(ipv4_frag_later),
	PASS(ipv6_tcp),
	PASS(ipv6_udp),
	PASS(ipv6_icmpv6),
	PASS(ipv6_no_next),
	PASS(ipv6_ext_chain_max),
	PASS(ipv6_frag_first),
	FRAG(ipv6_frag_later),
	PASS(vlan_one),
	PASS(vlan_qinq),
	NONIP(arp),
	NONIP(unknown_ethertype),
	NONIP(vlan_arp),
	BAD(vlan_three_tags),
	BAD(vlan_truncated),
	BAD(ipv4_truncated),
	BAD(ipv4_ihl_too_small),
	BAD(ipv4_bad_version),
	BAD(ipv4_ihl_beyond_frame),
	BAD(ipv4_totlen_beyond_frame),
	BAD(ipv4_totlen_below_ihl),
	BAD(ipv4_udp_outside_totlen),
	BAD(ipv4_tcp_truncated),
	BAD(ipv4_tcp_doff_too_small),
	BAD(ipv4_tcp_doff_beyond),
	BAD(ipv4_tiny_first_fragment),
	BAD(ipv4_icmp_truncated),
	BAD(ipv6_truncated),
	BAD(ipv6_bad_version),
	BAD(ipv6_payload_beyond_frame),
	BAD(ipv6_ext_chain_too_long),
	BAD(ipv6_ext_truncated),
	BAD(ipv6_ext_beyond_payload),
	BAD(ipv6_udp_truncated),
};

#endif /* XS_CASES_H */
