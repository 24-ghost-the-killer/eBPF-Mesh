/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Packet parsing: Ethernet, up to XS_MAX_VLAN_TAGS VLAN tags, IPv4, IPv6
 * (up to XS_MAX_IPV6_EXT_HDRS extension headers), TCP/UDP/ICMP/ICMPv6.
 *
 * Verifier rules followed here:
 *  - every packet access is preceded by a bounds check against data_end;
 *  - loops have compile-time bounds and are unrolled;
 *  - variable offsets added to packet pointers are bounded (VLAN: constant per
 *    iteration, IPv4 IHL: <= 60, TCP doff: <= 60, IPv6 ext header: <= 2048).
 *
 * Length fields in headers are validated with integer arithmetic against the
 * real frame length, so a header can never claim bytes that are not there.
 */
#ifndef XS_PARSE_H
#define XS_PARSE_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "abi.h"

/* ICMP header length (type, code, checksum, 4 bytes rest). <linux/icmp.h>
 * is not included: it pulls in glibc headers (<sys/socket.h>), which break
 * -target bpf builds on x86_64 (gnu/stubs-32.h). */
#define XS_ICMP_HDR_LEN 8

/*
 * Bounds a value for the verifier with a mask clang cannot optimise away.
 * Used on offsets read back from struct xs_pkt inside global functions,
 * which the verifier checks without knowing the caller's values.
 */
#define XS_BOUND(v, mask)                                                      \
	({                                                                     \
		__u64 __b = (v);                                               \
		asm volatile("%[b] &= " #mask : [b] "+r"(__b));                \
		__b;                                                           \
	})

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* IPv6 extension header numbers (linux/ipv6.h does not export NEXTHDR_*). */
#define XS_NH_HOP 0
#define XS_NH_ROUTING 43
#define XS_NH_FRAGMENT 44
#define XS_NH_AUTH 51
#define XS_NH_NONE 59
#define XS_NH_DEST 60

#define XS_IP4_MF 0x2000
#define XS_IP4_OFFSET 0x1FFF
#define XS_IP6_OFFSET 0xFFF8
#define XS_IP6_MF 0x0001

enum xs_parse_rc {
	XS_P_OK = 0,        /* parsed; L4 fields valid if l4_proto has ports */
	XS_P_NON_IP = 1,    /* not IPv4/IPv6 */
	XS_P_MALFORMED = 2, /* failed validation */
	XS_P_FRAGMENT = 3,  /* non-first fragment: L3 valid, no L4 header */
};

enum xs_frag {
	XS_FRAG_NONE = 0,
	XS_FRAG_FIRST = 1, /* offset 0, more fragments follow */
	XS_FRAG_LATER = 2, /* offset > 0 */
};

struct xs_pkt {
	__u16 l3_proto;   /* ETH_P_IP or ETH_P_IPV6 (host order), 0 if non-IP */
	__u8 l4_proto;    /* IPPROTO_*; for IPv6 the upper-layer header */
	__u8 tcp_flags;   /* byte 13 of the TCP header */
	__u8 vlan_count;
	__u8 frag;        /* enum xs_frag */
	__u8 icmp_type;   /* ICMP/ICMPv6 type (valid when l4_proto is ICMP*) */
	__be16 sport;     /* 0 unless TCP/UDP */
	__be16 dport;
	__u16 l3_off;     /* offset of the IP header from the frame start */
	__u16 l4_off;     /* offset of the L4 header (valid when XS_P_OK) */
	__u16 ip_len;     /* IP packet length per its header (excl. padding) */
	__be32 src4;
	__be32 dst4;
	struct in6_addr src6;
	struct in6_addr dst6;
};

/* Minimal 8-byte view shared by HOP/ROUTING/DEST/AUTH/FRAGMENT headers. */
struct xs_ext_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__be16 frag_off; /* only meaningful for the fragment header */
	__be32 _rest;
};

struct xs_vlan_hdr {
	__be16 tci;
	__be16 proto;
};

static __always_inline int xs_is_vlan(__be16 proto)
{
	return proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD);
}

static __always_inline int xs_is_ipv6_ext(__u8 nh)
{
	return nh == XS_NH_HOP || nh == XS_NH_ROUTING || nh == XS_NH_FRAGMENT ||
	       nh == XS_NH_AUTH || nh == XS_NH_DEST;
}

/*
 * Parse the L4 header at l4. avail = bytes of L3 payload according to the IP
 * length fields (already checked to fit inside the frame).
 */
static __always_inline int xs_parse_l4(void *l4, void *data_end, __u32 avail,
				       struct xs_pkt *pkt)
{
	switch (pkt->l4_proto) {
	case IPPROTO_TCP: {
		struct tcphdr *th = l4;
		__u32 hlen;

		if ((void *)(th + 1) > data_end || avail < sizeof(*th))
			return XS_P_MALFORMED;
		if (th->doff < 5)
			return XS_P_MALFORMED;
		hlen = th->doff * 4;
		if (l4 + hlen > data_end || hlen > avail)
			return XS_P_MALFORMED;
		pkt->sport = th->source;
		pkt->dport = th->dest;
		pkt->tcp_flags = ((__u8 *)th)[13];
		return XS_P_OK;
	}
	case IPPROTO_UDP: {
		struct udphdr *uh = l4;

		if ((void *)(uh + 1) > data_end || avail < sizeof(*uh))
			return XS_P_MALFORMED;
		pkt->sport = uh->source;
		pkt->dport = uh->dest;
		return XS_P_OK;
	}
	case IPPROTO_ICMP:
		if (pkt->l3_proto != ETH_P_IP)
			return XS_P_OK; /* ICMPv4 inside IPv6: not ours to judge */
		if (l4 + XS_ICMP_HDR_LEN > data_end ||
		    avail < XS_ICMP_HDR_LEN)
			return XS_P_MALFORMED;
		pkt->icmp_type = *(__u8 *)l4;
		return XS_P_OK;
	case IPPROTO_ICMPV6:
		if (pkt->l3_proto != ETH_P_IPV6)
			return XS_P_OK;
		if (l4 + sizeof(struct icmp6hdr) > data_end ||
		    avail < sizeof(struct icmp6hdr))
			return XS_P_MALFORMED;
		pkt->icmp_type = *(__u8 *)l4;
		return XS_P_OK;
	default:
		/* Other protocols (GRE, ESP, SCTP, ...) carry no parsed fields. */
		return XS_P_OK;
	}
}

static __always_inline int xs_parse_ipv4(void *data, void *data_end,
					 __u32 pkt_len, struct xs_pkt *pkt)
{
	struct iphdr *iph = data + pkt->l3_off;
	__u32 ihl, tot, frag;

	if ((void *)(iph + 1) > data_end)
		return XS_P_MALFORMED;
	if (iph->version != 4 || iph->ihl < 5)
		return XS_P_MALFORMED;
	ihl = iph->ihl * 4;
	tot = bpf_ntohs(iph->tot_len);
	/* Trailing Ethernet padding is fine; a too-long tot_len is not. */
	if (tot < ihl || tot > pkt_len - pkt->l3_off)
		return XS_P_MALFORMED;
	if ((void *)iph + ihl > data_end)
		return XS_P_MALFORMED;

	pkt->ip_len = tot;
	pkt->l4_proto = iph->protocol;
	pkt->src4 = iph->saddr;
	pkt->dst4 = iph->daddr;

	frag = bpf_ntohs(iph->frag_off);
	if (frag & XS_IP4_OFFSET) {
		pkt->frag = XS_FRAG_LATER;
		return XS_P_FRAGMENT;
	}
	if (frag & XS_IP4_MF)
		pkt->frag = XS_FRAG_FIRST;

	pkt->l4_off = pkt->l3_off + ihl;
	return xs_parse_l4((void *)iph + ihl, data_end, tot - ihl, pkt);
}

static __always_inline int xs_parse_ipv6(void *data, void *data_end,
					 __u32 pkt_len, struct xs_pkt *pkt)
{
	struct ipv6hdr *ip6 = data + pkt->l3_off;
	void *cur;
	__u32 remaining, off;
	__u8 nh;

	if ((void *)(ip6 + 1) > data_end)
		return XS_P_MALFORMED;
	if (ip6->version != 6)
		return XS_P_MALFORMED;
	remaining = bpf_ntohs(ip6->payload_len);
	if (sizeof(*ip6) + remaining > pkt_len - pkt->l3_off)
		return XS_P_MALFORMED;

	pkt->ip_len = sizeof(*ip6) + remaining;
	__builtin_memcpy(&pkt->src6, &ip6->saddr, sizeof(pkt->src6));
	__builtin_memcpy(&pkt->dst6, &ip6->daddr, sizeof(pkt->dst6));

	nh = ip6->nexthdr;
	cur = ip6 + 1;
	off = pkt->l3_off + sizeof(*ip6);

#pragma unroll
	for (int i = 0; i < XS_MAX_IPV6_EXT_HDRS; i++) {
		struct xs_ext_hdr *eh = cur;
		__u32 hlen;

		if (!xs_is_ipv6_ext(nh))
			break;
		if ((void *)(eh + 1) > data_end)
			return XS_P_MALFORMED;

		if (nh == XS_NH_FRAGMENT) {
			__u16 fo = bpf_ntohs(eh->frag_off);

			hlen = 8;
			if (hlen > remaining)
				return XS_P_MALFORMED;
			pkt->l4_proto = eh->nexthdr;
			/* A later fragment has no L4 header to parse. */
			if (fo & XS_IP6_OFFSET) {
				pkt->frag = XS_FRAG_LATER;
				return XS_P_FRAGMENT;
			}
			if (fo & XS_IP6_MF)
				pkt->frag = XS_FRAG_FIRST;
		} else if (nh == XS_NH_AUTH) {
			hlen = ((__u32)eh->hdrlen + 2) * 4;
		} else {
			hlen = ((__u32)eh->hdrlen + 1) * 8;
		}
		if (hlen > remaining)
			return XS_P_MALFORMED;

		nh = eh->nexthdr;
		remaining -= hlen;
		off += hlen;
		cur += hlen;
	}
	/* Chain longer than we are willing to walk. */
	if (xs_is_ipv6_ext(nh))
		return XS_P_MALFORMED;

	pkt->l4_proto = nh;
	if (nh == XS_NH_NONE)
		return XS_P_OK;
	pkt->l4_off = off;
	return xs_parse_l4(cur, data_end, remaining, pkt);
}

/*
 * Parse a frame. Fills *pkt and returns enum xs_parse_rc.
 * pkt must be zero-initialised by the caller.
 */
static __always_inline int xs_parse(void *data, void *data_end, __u32 pkt_len,
				    struct xs_pkt *pkt)
{
	struct ethhdr *eth = data;
	__be16 proto;
	__u32 off;

	if ((void *)(eth + 1) > data_end)
		return XS_P_MALFORMED;
	proto = eth->h_proto;
	off = sizeof(*eth);

#pragma unroll
	for (int i = 0; i < XS_MAX_VLAN_TAGS; i++) {
		struct xs_vlan_hdr *vh;

		if (!xs_is_vlan(proto))
			break;
		vh = data + off;
		if ((void *)(vh + 1) > data_end)
			return XS_P_MALFORMED;
		proto = vh->proto;
		off += sizeof(*vh);
		pkt->vlan_count++;
	}
	if (xs_is_vlan(proto))
		return XS_P_MALFORMED; /* more tags than we support */

	pkt->l3_off = off;
	if (proto == bpf_htons(ETH_P_IP)) {
		pkt->l3_proto = ETH_P_IP;
		return xs_parse_ipv4(data, data_end, pkt_len, pkt);
	}
	if (proto == bpf_htons(ETH_P_IPV6)) {
		pkt->l3_proto = ETH_P_IPV6;
		return xs_parse_ipv6(data, data_end, pkt_len, pkt);
	}
	return XS_P_NON_IP;
}

#endif /* XS_PARSE_H */
