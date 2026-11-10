/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * cases.h - the dataplane packet corpus.
 *
 * One table drives two test suites:
 *   tests/bpf/parser_host.c  runs em_parse_packet() + em_account_parse() on
 *                            the host and checks the parse result, every
 *                            extracted field and the exact counter slots;
 *   tests/bpf/test_xdp.c     runs the compiled XDP program in the kernel via
 *                            BPF_PROG_TEST_RUN and checks verdict, output
 *                            bytes and the exact counter deltas.
 *
 * `counters` lists EVERY classification slot the frame must increment, in
 * addition to the implicit RX, PARSE_BASE + rc and VERDICT_PASS. Both suites
 * check that no other slot moves. Field expectations are only compared for
 * non-error outcomes (OK, NOT_IP, UNSUP_*); for malformed frames the exact
 * error code is the contract.
 *
 * Addresses come from documentation ranges only (RFC 5737 / RFC 3849).
 */
#ifndef EM_TEST_CASES_H
#define EM_TEST_CASES_H

#include "compat.h"
#include "abi.h"
#include "parsers.h"
#include "pktbuild.h"

#define SRC4 0xC6336401u /* 198.51.100.1 */
#define DST4 0xCB00710Au /* 203.0.113.10 */

#define FIN EM_TCP_FIN
#define SYN EM_TCP_SYN
#define RST EM_TCP_RST
#define PSH EM_TCP_PSH
#define ACK EM_TCP_ACK
#define URG EM_TCP_URG

#define EM_CASE_MAX_COUNTERS 6

struct em_case {
	const char *name;
	void (*build)(struct pb *b);
	int rc;
	/* every classification slot expected to increase by exactly one packet */
	uint16_t counters[EM_CASE_MAX_COUNTERS];
	/* parsed fields (non-error outcomes only) */
	uint8_t l3, l4_proto, frag, vlan_depth, n_ext, anomalies, tcp_flags, l4_parsed;
	uint16_t sport, dport; /* host byte order */
};

#define B(fn) static void fn(struct pb *b)

/* ---------------- L2 ---------------- */
B(eth_trunc)        { pb_put(b, 10); }
B(eth_only_ipv4)    { pb_eth(b, EM_ETH_P_IPV4); }
B(arp)              { pb_eth(b, EM_ETH_P_ARP); pb_payload(b, 28); }
B(llc_8023)         { pb_eth(b, 0x0026); pb_payload(b, 46); }

/* ---------------- IPv4 valid ---------------- */
B(v4_tcp_syn)       { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v4_tcp_syn_opts)  { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 10); pb_finalize(b); }
B(v4_tcp_synack)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, DST4, SRC4, 0, 0); pb_tcp(b, 443, 40000, SYN | ACK, 5); pb_finalize(b); }
B(v4_tcp_ack_data)  { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, ACK | PSH, 5); pb_payload(b, 100); pb_finalize(b); }
B(v4_tcp_fin_ack)   { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, FIN | ACK, 5); pb_finalize(b); }
B(v4_tcp_rst)       { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, RST, 5); pb_finalize(b); }
B(v4_udp)           { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 5353, 53); pb_payload(b, 32); pb_finalize(b); }
B(v4_icmp_echo)     { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 1, SRC4, DST4, 0, 0); pb_icmp(b, 8, 0); pb_payload(b, 56); pb_finalize(b); }
B(v4_gre)           { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 47, SRC4, DST4, 0, 0); pb_payload(b, 24); pb_finalize(b); }
B(v4_options)       { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 2, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v4_eth_padding)   { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 1, SRC4, DST4, 0, 0); pb_icmp(b, 8, 0); pb_finalize(b); pb_put(b, 18); }
B(v4_land)          { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, SRC4, 0, 0); pb_tcp(b, 139, 139, SYN, 5); pb_finalize(b); }
B(v4_ttl_zero)      { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); b->buf[b->ip4_off + 8] = 0; pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v4_port_zero)     { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 40000, 0); pb_finalize(b); }

/* ---------------- IPv4 fragments ---------------- */
B(v4_frag_first)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0x2000); pb_udp(b, 5000, 6000); pb_payload(b, 200); pb_finalize(b);
		      pb_put16(b, b->udp_off + 4, 3000); /* datagram length > fragment: legal */ }
B(v4_frag_later)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 185); pb_payload(b, 100); pb_finalize(b); }
B(v4_frag_tiny)     { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0x2000); pb_payload(b, 8); pb_finalize(b); }

/* ---------------- IPv4 malformed ---------------- */
B(v4_trunc)         { pb_eth(b, EM_ETH_P_IPV4); pb_put(b, 10)[0] = 0x45; }
B(v4_bad_version)   { v4_tcp_syn(b); b->buf[14] = 0x55; }
B(v4_ihl_lt5)       { v4_tcp_syn(b); b->buf[14] = 0x44; }
B(v4_ihl_beyond)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_payload(b, 4); pb_finalize(b); b->buf[14] = 0x4F; }
B(v4_totlen_big)    { v4_udp(b); pb_put16(b, 14 + 2, (uint16_t)(b->len - 14 + 100)); }
B(v4_totlen_lt_ihl) { v4_udp(b); pb_put16(b, 14 + 2, 16); }

/* ---------------- TCP/UDP/ICMP malformed / anomalous ---------------- */
B(v4_tcp_trunc)     { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_payload(b, 10); pb_finalize(b); }
B(v4_tcp_doff_lt5)  { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 1, 2, SYN, 4); pb_finalize(b); }
B(v4_tcp_doff_big)  { v4_tcp_syn(b); b->buf[14 + 20 + 12] = 0xF0; /* 60-byte header in a 20-byte segment */ }
B(v4_tcp_null)      { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, 0, 5); pb_finalize(b); }
B(v4_tcp_xmas)      { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, FIN | PSH | URG, 5); pb_finalize(b); }
B(v4_tcp_synfin)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, SYN | FIN, 5); pb_finalize(b); }
B(v4_tcp_synrst)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, SYN | RST, 5); pb_finalize(b); }
B(v4_tcp_fin_only)  { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, FIN, 5); pb_finalize(b); }
B(v4_udp_trunc)     { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_payload(b, 4); pb_finalize(b); }
B(v4_udp_len_lt8)   { v4_udp(b); pb_put16(b, b->udp_off + 4, 4); }
B(v4_udp_len_big)   { v4_udp(b); pb_put16(b, b->udp_off + 4, (uint16_t)(b->len - b->udp_off + 10)); }
B(v4_udp_len_small) { v4_udp(b); pb_put16(b, b->udp_off + 4, 8); }
B(v4_icmp_trunc)    { pb_eth(b, EM_ETH_P_IPV4); pb_ipv4(b, 1, SRC4, DST4, 0, 0); pb_payload(b, 4); pb_finalize(b); }

/* ---------------- VLAN ---------------- */
B(vlan1_v4_tcp)     { pb_eth(b, EM_ETH_P_8021Q); pb_vlan(b, 100, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(qinq_v4_udp)      { pb_eth(b, EM_ETH_P_8021AD); pb_vlan(b, 200, EM_ETH_P_8021Q); pb_vlan(b, 100, EM_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 1, 2); pb_finalize(b); }
B(qinq9100_v6_udp)  { pb_eth(b, EM_ETH_P_QINQ_9100); pb_vlan(b, 7, EM_ETH_P_8021Q); pb_vlan(b, 8, EM_ETH_P_IPV6); pb_ipv6(b, 17, 1, 2); pb_udp(b, 1, 2); pb_finalize(b); }
B(vlan3_unsup)      { pb_eth(b, EM_ETH_P_8021AD); pb_vlan(b, 1, EM_ETH_P_8021Q); pb_vlan(b, 2, EM_ETH_P_8021Q); pb_vlan(b, 3, EM_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 1, 2, SYN, 5); pb_finalize(b); }
B(vlan_trunc)       { pb_eth(b, EM_ETH_P_8021Q); pb_put(b, 2); }
B(vlan_arp)         { pb_eth(b, EM_ETH_P_8021Q); pb_vlan(b, 5, EM_ETH_P_ARP); pb_payload(b, 28); }

/* ---------------- IPv6 valid ---------------- */
B(v6_tcp_syn)       { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 6, 1, 2); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_udp)           { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 17, 1, 2); pb_udp(b, 5353, 53); pb_payload(b, 32); pb_finalize(b); }
B(v6_icmpv6_echo)   { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 58, 1, 2); pb_icmp(b, 128, 0); pb_payload(b, 56); pb_finalize(b); }
B(v6_padding)       { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 58, 1, 2); pb_icmp(b, 128, 0); pb_finalize(b); pb_put(b, 10); }
B(v6_land)          { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 6, 1, 1); pb_tcp(b, 80, 80, SYN, 5); pb_finalize(b); }
B(v6_hop_zero)      { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 6, 1, 2); b->buf[b->ip6_off + 7] = 0; pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_esp)           { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 50, 1, 2); pb_payload(b, 40); pb_finalize(b); }
B(v6_no_next)       { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 59, 1, 2); pb_payload(b, 8); pb_finalize(b); }
B(v6_icmp4_in_v6)   { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 1, 1, 2); pb_icmp(b, 8, 0); pb_finalize(b); }

/* ---------------- IPv6 extension headers / fragments ---------------- */
B(v6_hbh_tcp)       { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 6, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_chain3_tcp)    { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 60, 0); pb_ipv6_ext(b, 43, 1); pb_ipv6_ext(b, 6, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_ah_udp)        { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 51, 1, 2); pb_ipv6_ah(b, 17, 4); pb_udp(b, 500, 500); pb_finalize(b); }
B(v6_frag_first)    { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 17, 0, 1); pb_udp(b, 5000, 6000); pb_payload(b, 64); pb_finalize(b); }
B(v6_frag_later)    { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 17, 100, 0); pb_payload(b, 64); pb_finalize(b); }
B(v6_atomic_frag)   { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 6, 0, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_frag_tiny)     { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 6, 0, 1); pb_payload(b, 8); pb_finalize(b); }
B(v6_ext6_udp)      { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 60, 1, 2); for (int i = 0; i < 5; i++) pb_ipv6_ext(b, 60, 0); pb_ipv6_ext(b, 17, 0); pb_udp(b, 1, 2); pb_finalize(b); }
B(v6_ext7_unsup)    { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 60, 1, 2); for (int i = 0; i < 6; i++) pb_ipv6_ext(b, 60, 0); pb_ipv6_ext(b, 17, 0); pb_udp(b, 1, 2); pb_finalize(b); }
B(v6_ext_hdr_trunc) { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_put(b, 4)[0] = 6; pb_finalize(b); }
B(v6_ext_len_frame) { uint8_t *p; pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); p = pb_put(b, 16); p[0] = 6; p[1] = 10; pb_finalize(b); }
B(v6_ext_len_plen)  { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 17, 1); pb_udp(b, 1, 2); pb_finalize(b); pb_put16(b, b->ip6_off + 4, 8); }

/* ---------------- IPv6 malformed ---------------- */
B(v6_trunc)         { pb_eth(b, EM_ETH_P_IPV6); pb_put(b, 20)[0] = 0x60; }
B(v6_bad_version)   { v6_udp(b); b->buf[14] = 0x40; }
B(v6_plen_big)      { v6_udp(b); pb_put16(b, b->ip6_off + 4, (uint16_t)(b->len - b->ip6_off - 40 + 100)); }
B(v6_plen_zero)     { v6_udp(b); pb_put16(b, b->ip6_off + 4, 0); }
B(v6_tcp_trunc)     { pb_eth(b, EM_ETH_P_IPV6); pb_ipv6(b, 6, 1, 2); pb_payload(b, 10); pb_finalize(b); }
B(v6_udp_len_big)   { v6_udp(b); pb_put16(b, b->udp_off + 4, 200); }

#undef B

#define V4 EM_L3_IPV4
#define V6 EM_L3_IPV6

/* Short counter names for the table below. */
#define C_V1   EM_CNT_L2_VLAN1
#define C_V2   EM_CNT_L2_VLAN2
#define C_IP4  EM_CNT_L3_IPV4
#define C_IP6  EM_CNT_L3_IPV6
#define C_ARP  EM_CNT_L3_ARP
#define C_L3X  EM_CNT_L3_OTHER
#define C_TCP  EM_CNT_L4_TCP
#define C_UDP  EM_CNT_L4_UDP
#define C_ICMP EM_CNT_L4_ICMP
#define C_IC6  EM_CNT_L4_ICMPV6
#define C_L4X  EM_CNT_L4_OTHER
#define C_FF   EM_CNT_FRAG_FIRST
#define C_FL   EM_CNT_FRAG_LATER
#define C_EXT  EM_CNT_IPV6_EXT
#define C_SYN  EM_CNT_TCP_SYN
#define C_SA   EM_CNT_TCP_SYNACK
#define C_ACK  EM_CNT_TCP_ACK
#define C_FIN  EM_CNT_TCP_FIN
#define C_RST  EM_CNT_TCP_RST
#define C_OPT  EM_CNT_ANOM_IPV4_OPTIONS
#define C_BADF EM_CNT_ANOM_TCP_BAD_FLAGS
#define C_ULEN EM_CNT_ANOM_UDP_LEN_MISMATCH
#define C_LAND EM_CNT_ANOM_LAND
#define C_TTL0 EM_CNT_ANOM_TTL_ZERO
#define C_P0   EM_CNT_ANOM_PORT_ZERO

static const struct em_case em_cases[] = {
	/* L2 */
	{ "eth_trunc",        eth_trunc,        EM_PARSE_ERR_ETH_TRUNC },
	{ "eth_only_ipv4",    eth_only_ipv4,    EM_PARSE_ERR_IPV4_TRUNC },
	{ "arp",              arp,              EM_PARSE_NOT_IP, { C_ARP } },
	{ "llc_8023",         llc_8023,         EM_PARSE_NOT_IP, { C_L3X } },

	/* IPv4 valid */
	{ "v4_tcp_syn",       v4_tcp_syn,       EM_PARSE_OK, { C_IP4, C_TCP, C_SYN },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_syn_opts",  v4_tcp_syn_opts,  EM_PARSE_OK, { C_IP4, C_TCP, C_SYN },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_synack",    v4_tcp_synack,    EM_PARSE_OK, { C_IP4, C_TCP, C_SA },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN | ACK, .l4_parsed = 1, .sport = 443, .dport = 40000 },
	{ "v4_tcp_ack_data",  v4_tcp_ack_data,  EM_PARSE_OK, { C_IP4, C_TCP, C_ACK },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = ACK | PSH, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_fin_ack",   v4_tcp_fin_ack,   EM_PARSE_OK, { C_IP4, C_TCP, C_FIN },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = FIN | ACK, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_rst",       v4_tcp_rst,       EM_PARSE_OK, { C_IP4, C_TCP, C_RST },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = RST, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_udp",           v4_udp,           EM_PARSE_OK, { C_IP4, C_UDP },
	  .l3 = V4, .l4_proto = 17, .l4_parsed = 1, .sport = 5353, .dport = 53 },
	{ "v4_icmp_echo",     v4_icmp_echo,     EM_PARSE_OK, { C_IP4, C_ICMP },
	  .l3 = V4, .l4_proto = 1, .l4_parsed = 1 },
	{ "v4_gre",           v4_gre,           EM_PARSE_OK, { C_IP4, C_L4X },
	  .l3 = V4, .l4_proto = 47 },
	{ "v4_options",       v4_options,       EM_PARSE_OK, { C_IP4, C_TCP, C_SYN, C_OPT },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443,
	  .anomalies = EM_ANOM_IPV4_OPTIONS },
	{ "v4_eth_padding",   v4_eth_padding,   EM_PARSE_OK, { C_IP4, C_ICMP },
	  .l3 = V4, .l4_proto = 1, .l4_parsed = 1 },
	{ "v4_land",          v4_land,          EM_PARSE_OK, { C_IP4, C_TCP, C_SYN, C_LAND },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 139, .dport = 139,
	  .anomalies = EM_ANOM_LAND },
	{ "v4_ttl_zero",      v4_ttl_zero,      EM_PARSE_OK, { C_IP4, C_TCP, C_SYN, C_TTL0 },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443,
	  .anomalies = EM_ANOM_TTL_ZERO },
	{ "v4_port_zero",     v4_port_zero,     EM_PARSE_OK, { C_IP4, C_UDP, C_P0 },
	  .l3 = V4, .l4_proto = 17, .l4_parsed = 1, .sport = 40000, .dport = 0,
	  .anomalies = EM_ANOM_PORT_ZERO },

	/* IPv4 fragments */
	{ "v4_frag_first",    v4_frag_first,    EM_PARSE_OK, { C_IP4, C_UDP, C_FF },
	  .l3 = V4, .l4_proto = 17, .frag = EM_FRAG_FIRST, .l4_parsed = 1, .sport = 5000, .dport = 6000 },
	{ "v4_frag_later",    v4_frag_later,    EM_PARSE_OK, { C_IP4, C_UDP, C_FL },
	  .l3 = V4, .l4_proto = 17, .frag = EM_FRAG_LATER },
	{ "v4_frag_tiny",     v4_frag_tiny,     EM_PARSE_ERR_FRAG_TINY, { C_IP4 } },

	/* IPv4 malformed */
	{ "v4_trunc",         v4_trunc,         EM_PARSE_ERR_IPV4_TRUNC },
	{ "v4_bad_version",   v4_bad_version,   EM_PARSE_ERR_IPV4_VERSION },
	{ "v4_ihl_lt5",       v4_ihl_lt5,       EM_PARSE_ERR_IPV4_IHL },
	{ "v4_ihl_beyond",    v4_ihl_beyond,    EM_PARSE_ERR_IPV4_TRUNC },
	{ "v4_totlen_big",    v4_totlen_big,    EM_PARSE_ERR_IPV4_TOTLEN },
	{ "v4_totlen_lt_ihl", v4_totlen_lt_ihl, EM_PARSE_ERR_IPV4_TOTLEN },

	/* L4 malformed / anomalous */
	{ "v4_tcp_trunc",     v4_tcp_trunc,     EM_PARSE_ERR_TCP_TRUNC, { C_IP4 } },
	{ "v4_tcp_doff_lt5",  v4_tcp_doff_lt5,  EM_PARSE_ERR_TCP_DOFF,  { C_IP4 } },
	{ "v4_tcp_doff_big",  v4_tcp_doff_big,  EM_PARSE_ERR_TCP_DOFF,  { C_IP4 } },
	{ "v4_tcp_null",      v4_tcp_null,      EM_PARSE_OK, { C_IP4, C_TCP, C_BADF },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = 0, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = EM_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_xmas",      v4_tcp_xmas,      EM_PARSE_OK, { C_IP4, C_TCP, C_FIN, C_BADF },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = FIN | PSH | URG, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = EM_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_synfin",    v4_tcp_synfin,    EM_PARSE_OK, { C_IP4, C_TCP, C_SYN, C_FIN, C_BADF },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN | FIN, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = EM_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_synrst",    v4_tcp_synrst,    EM_PARSE_OK, { C_IP4, C_TCP, C_SYN, C_RST, C_BADF },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN | RST, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = EM_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_fin_only",  v4_tcp_fin_only,  EM_PARSE_OK, { C_IP4, C_TCP, C_FIN, C_BADF },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = FIN, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = EM_ANOM_TCP_BAD_FLAGS },
	{ "v4_udp_trunc",     v4_udp_trunc,     EM_PARSE_ERR_UDP_TRUNC, { C_IP4 } },
	{ "v4_udp_len_lt8",   v4_udp_len_lt8,   EM_PARSE_ERR_UDP_LEN,   { C_IP4 } },
	{ "v4_udp_len_big",   v4_udp_len_big,   EM_PARSE_ERR_UDP_LEN,   { C_IP4 } },
	{ "v4_udp_len_small", v4_udp_len_small, EM_PARSE_OK, { C_IP4, C_UDP, C_ULEN },
	  .l3 = V4, .l4_proto = 17, .l4_parsed = 1, .sport = 5353, .dport = 53,
	  .anomalies = EM_ANOM_UDP_LEN_MISMATCH },
	{ "v4_icmp_trunc",    v4_icmp_trunc,    EM_PARSE_ERR_ICMP_TRUNC, { C_IP4 } },

	/* VLAN */
	{ "vlan1_v4_tcp",     vlan1_v4_tcp,     EM_PARSE_OK, { C_V1, C_IP4, C_TCP, C_SYN },
	  .l3 = V4, .l4_proto = 6, .vlan_depth = 1, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "qinq_v4_udp",      qinq_v4_udp,      EM_PARSE_OK, { C_V2, C_IP4, C_UDP },
	  .l3 = V4, .l4_proto = 17, .vlan_depth = 2, .l4_parsed = 1, .sport = 1, .dport = 2 },
	{ "qinq9100_v6_udp",  qinq9100_v6_udp,  EM_PARSE_OK, { C_V2, C_IP6, C_UDP },
	  .l3 = V6, .l4_proto = 17, .vlan_depth = 2, .l4_parsed = 1, .sport = 1, .dport = 2 },
	{ "vlan3_unsup",      vlan3_unsup,      EM_PARSE_UNSUP_VLAN_DEPTH, { C_V2 },
	  .vlan_depth = 2 },
	{ "vlan_trunc",       vlan_trunc,       EM_PARSE_ERR_VLAN_TRUNC },
	{ "vlan_arp",         vlan_arp,         EM_PARSE_NOT_IP, { C_V1, C_ARP },
	  .vlan_depth = 1 },

	/* IPv6 valid */
	{ "v6_tcp_syn",       v6_tcp_syn,       EM_PARSE_OK, { C_IP6, C_TCP, C_SYN },
	  .l3 = V6, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_udp",           v6_udp,           EM_PARSE_OK, { C_IP6, C_UDP },
	  .l3 = V6, .l4_proto = 17, .l4_parsed = 1, .sport = 5353, .dport = 53 },
	{ "v6_icmpv6_echo",   v6_icmpv6_echo,   EM_PARSE_OK, { C_IP6, C_IC6 },
	  .l3 = V6, .l4_proto = 58, .l4_parsed = 1 },
	{ "v6_padding",       v6_padding,       EM_PARSE_OK, { C_IP6, C_IC6 },
	  .l3 = V6, .l4_proto = 58, .l4_parsed = 1 },
	{ "v6_land",          v6_land,          EM_PARSE_OK, { C_IP6, C_TCP, C_SYN, C_LAND },
	  .l3 = V6, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 80, .dport = 80,
	  .anomalies = EM_ANOM_LAND },
	{ "v6_hop_zero",      v6_hop_zero,      EM_PARSE_OK, { C_IP6, C_TCP, C_SYN, C_TTL0 },
	  .l3 = V6, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443,
	  .anomalies = EM_ANOM_TTL_ZERO },
	{ "v6_esp",           v6_esp,           EM_PARSE_OK, { C_IP6, C_L4X },
	  .l3 = V6, .l4_proto = 50 },
	{ "v6_no_next",       v6_no_next,       EM_PARSE_OK, { C_IP6, C_L4X },
	  .l3 = V6, .l4_proto = 59 },
	{ "v6_icmp4_in_v6",   v6_icmp4_in_v6,   EM_PARSE_OK, { C_IP6, C_L4X },
	  .l3 = V6, .l4_proto = 1 },

	/* IPv6 extension headers / fragments */
	{ "v6_hbh_tcp",       v6_hbh_tcp,       EM_PARSE_OK, { C_IP6, C_TCP, C_SYN, C_EXT },
	  .l3 = V6, .l4_proto = 6, .n_ext = 1, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_chain3_tcp",    v6_chain3_tcp,    EM_PARSE_OK, { C_IP6, C_TCP, C_SYN, C_EXT },
	  .l3 = V6, .l4_proto = 6, .n_ext = 3, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_ah_udp",        v6_ah_udp,        EM_PARSE_OK, { C_IP6, C_UDP, C_EXT },
	  .l3 = V6, .l4_proto = 17, .n_ext = 1, .l4_parsed = 1, .sport = 500, .dport = 500 },
	{ "v6_frag_first",    v6_frag_first,    EM_PARSE_OK, { C_IP6, C_UDP, C_EXT, C_FF },
	  .l3 = V6, .l4_proto = 17, .n_ext = 1, .frag = EM_FRAG_FIRST, .l4_parsed = 1, .sport = 5000, .dport = 6000 },
	{ "v6_frag_later",    v6_frag_later,    EM_PARSE_OK, { C_IP6, C_UDP, C_EXT, C_FL },
	  .l3 = V6, .l4_proto = 17, .n_ext = 1, .frag = EM_FRAG_LATER },
	{ "v6_atomic_frag",   v6_atomic_frag,   EM_PARSE_OK, { C_IP6, C_TCP, C_SYN, C_EXT },
	  .l3 = V6, .l4_proto = 6, .n_ext = 1, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_frag_tiny",     v6_frag_tiny,     EM_PARSE_ERR_FRAG_TINY, { C_IP6 } },
	{ "v6_ext6_udp",      v6_ext6_udp,      EM_PARSE_OK, { C_IP6, C_UDP, C_EXT },
	  .l3 = V6, .l4_proto = 17, .n_ext = 6, .l4_parsed = 1, .sport = 1, .dport = 2 },
	{ "v6_ext7_unsup",    v6_ext7_unsup,    EM_PARSE_UNSUP_IPV6_EXT_DEPTH, { C_IP6 },
	  .l3 = V6, .l4_proto = 60, .n_ext = 6 },
	{ "v6_ext_hdr_trunc", v6_ext_hdr_trunc, EM_PARSE_ERR_IPV6_EXT_TRUNC, { C_IP6 } },
	{ "v6_ext_len_frame", v6_ext_len_frame, EM_PARSE_ERR_IPV6_EXT_TRUNC, { C_IP6 } },
	{ "v6_ext_len_plen",  v6_ext_len_plen,  EM_PARSE_ERR_IPV6_EXT_TRUNC, { C_IP6 } },

	/* IPv6 malformed */
	{ "v6_trunc",         v6_trunc,         EM_PARSE_ERR_IPV6_TRUNC },
	{ "v6_bad_version",   v6_bad_version,   EM_PARSE_ERR_IPV6_VERSION },
	{ "v6_plen_big",      v6_plen_big,      EM_PARSE_ERR_IPV6_PLEN },
	{ "v6_plen_zero",     v6_plen_zero,     EM_PARSE_ERR_IPV6_PLEN },
	{ "v6_tcp_trunc",     v6_tcp_trunc,     EM_PARSE_ERR_TCP_TRUNC, { C_IP6 } },
	{ "v6_udp_len_big",   v6_udp_len_big,   EM_PARSE_ERR_UDP_LEN,   { C_IP6 } },
};

#define EM_N_CASES (sizeof(em_cases) / sizeof(em_cases[0]))

/*
 * Expected per-slot packet delta for one case: 1 for RX, the parse-outcome
 * slot, VERDICT_PASS and every listed classification slot; 0 elsewhere.
 * Shared by both suites so "exactly these slots moved" means the same thing.
 */
static inline void em_case_expected(const struct em_case *c, uint8_t want[EM_CNT_SLOTS])
{
	memset(want, 0, EM_CNT_SLOTS);
	want[EM_CNT_RX] = 1;
	want[EM_CNT_PARSE_BASE + c->rc] = 1;
	want[EM_CNT_VERDICT_PASS] = 1;
	for (int k = 0; k < EM_CASE_MAX_COUNTERS && c->counters[k]; k++)
		want[c->counters[k]] = 1;
}

#undef V4
#undef V6

#endif /* EM_TEST_CASES_H */
