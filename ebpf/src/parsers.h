/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * parsers.h - bounded, verifier-safe Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP
 * header parsing.
 *
 * Rules every function in this file follows:
 *
 *   * Every read of packet memory is preceded by a check of the form
 *     `(void *)(hdr + 1) > data_end` on the exact pointer being dereferenced.
 *     The verifier only accepts packet loads within a range proven by such a
 *     comparison, so this is both a safety and a load-time requirement.
 *   * Length fields from the packet (IHL, TCP data offset, IPv6 extension
 *     hdrlen, IPv4 total length, IPv6 payload length, UDP length) are never
 *     trusted: they are masked/bounded, validated against the minimum legal
 *     value and against data_end before being used to advance the cursor.
 *   * Every loop has a compile-time trip count (VLAN tags, IPv6 extension
 *     headers) and is unrolled.
 *   * No helpers, no maps: pure functions of (data, data_end). This lets the
 *     same code be unit-tested on the host (tests/bpf/parser_host.c).
 *
 * Header structs are defined here instead of using UAPI/vmlinux types: they
 * describe wire formats, not kernel ABI, and defining them locally avoids
 * endian-dependent bitfields (struct iphdr's ihl:4/version:4) and makes the
 * host build possible.
 *
 * Linear-buffer assumption: the program is SEC("xdp"), not SEC("xdp.frags"),
 * so the kernel refuses to attach it to a device whose MTU needs multi-buffer
 * XDP, and [data, data_end) is always the whole frame.
 */
#ifndef EM_PARSERS_H
#define EM_PARSERS_H

#include "compat.h"
#include "abi.h"

/* ---- constants (prefixed to avoid clashing with UAPI macros) ---- */

#define EM_ETH_P_IPV4       0x0800
#define EM_ETH_P_ARP        0x0806
#define EM_ETH_P_IPV6       0x86DD
#define EM_ETH_P_8021Q      0x8100
#define EM_ETH_P_8021AD     0x88A8
#define EM_ETH_P_QINQ_9100  0x9100 /* pre-802.1ad vendor QinQ outer tag */

#define EM_IPPROTO_HOPOPTS  0
#define EM_IPPROTO_ICMP     1
#define EM_IPPROTO_TCP      6
#define EM_IPPROTO_UDP      17
#define EM_IPPROTO_ROUTING  43
#define EM_IPPROTO_FRAGMENT 44
#define EM_IPPROTO_AH       51
#define EM_IPPROTO_ICMPV6   58
#define EM_IPPROTO_DSTOPTS  60

#define EM_TCP_FIN 0x01
#define EM_TCP_SYN 0x02
#define EM_TCP_RST 0x04
#define EM_TCP_PSH 0x08
#define EM_TCP_ACK 0x10
#define EM_TCP_URG 0x20

#define EM_MAX_VLAN_DEPTH    2      /* 802.1Q + QinQ */
#define EM_IPV6_MAX_EXT      6      /* HBH, DST, RH, FRAG, AH, DST covers real traffic */
#define EM_IPV6_EXT_OFF_MASK 0x3FFF /* > EM_IPV6_MAX_EXT * 2048 */

#define EM_IPV4_FRAG_MF     0x2000
#define EM_IPV4_FRAG_OFFSET 0x1FFF
#define EM_IPV6_FRAG_OFFSET 0xFFF8
#define EM_IPV6_FRAG_MF     0x0001

/* ---- wire formats ---- */

struct em_hdr_eth {
	__u8   dst[6];
	__u8   src[6];
	__be16 proto;
};

struct em_hdr_vlan {
	__be16 tci;
	__be16 proto; /* encapsulated ethertype */
};

struct em_hdr_ipv4 {
	__u8   ver_ihl;
	__u8   tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8   ttl;
	__u8   protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct em_hdr_ipv6 {
	__be32 ver_tc_flow;
	__be16 payload_len;
	__u8   nexthdr;
	__u8   hop_limit;
	__be32 saddr[4];
	__be32 daddr[4];
};

/* Generic IPv6 extension header prefix (HBH, routing, dst opts, AH). */
struct em_hdr_ipv6_ext {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct em_hdr_ipv6_frag {
	__u8   nexthdr;
	__u8   reserved;
	__be16 frag_off; /* offset(13) | res(2) | M(1) */
	__be32 id;
};

struct em_hdr_tcp {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8   doff_res; /* data offset in the high nibble */
	__u8   flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct em_hdr_udp {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

/* ICMPv4 and ICMPv6 share this 8-byte layout. */
struct em_hdr_icmp {
	__u8   type;
	__u8   code;
	__sum16 checksum;
	__be32 rest;
};

/* ---- parse output ---- */

enum em_l3 {
	EM_L3_NONE = 0,
	EM_L3_IPV4 = 1,
	EM_L3_IPV6 = 2,
};

enum em_frag {
	EM_FRAG_NONE  = 0,
	EM_FRAG_FIRST = 1, /* offset 0, more-fragments set: carries the L4 header */
	EM_FRAG_LATER = 2, /* offset != 0: no L4 header */
};

enum em_anomaly {
	EM_ANOM_IPV4_OPTIONS     = 1u << 0,
	EM_ANOM_TCP_BAD_FLAGS    = 1u << 1,
	EM_ANOM_UDP_LEN_MISMATCH = 1u << 2, /* UDP length < IP payload length */
	EM_ANOM_LAND             = 1u << 3, /* source address == destination address */
	EM_ANOM_TTL_ZERO         = 1u << 4, /* IPv4 TTL / IPv6 hop limit == 0 */
	EM_ANOM_PORT_ZERO        = 1u << 5, /* TCP/UDP source or dest port == 0 */
};

union em_addr {
	__be32 v4;     /* IPv4 lives in the first word, rest zero */
	__be32 v6[4];
};

/*
 * Parsed packet metadata. Lives on the BPF stack (64 bytes of the 512-byte
 * budget). Ports and addresses stay in network byte order; converting is the
 * consumer's job and usually unnecessary (map keys use wire order).
 */
struct em_pkt {
	union em_addr saddr;
	union em_addr daddr;
	__u32  l4_len;        /* L4 bytes according to the IP header(s) */
	__be16 eth_proto;     /* innermost ethertype */
	__be16 sport;
	__be16 dport;
	__u16  vlan_id[EM_MAX_VLAN_DEPTH]; /* outer, inner (host order, 12 bits) */
	__u8   vlan_depth;
	__u8   l3;            /* enum em_l3 */
	__u8   l4_proto;      /* transport protocol after extension headers */
	__u8   frag;          /* enum em_frag */
	__u8   tcp_flags;
	__u8   ttl;           /* IPv4 TTL / IPv6 hop limit */
	__u8   icmp_type;
	__u8   icmp_code;
	__u8   n_ext;         /* IPv6 extension headers traversed */
	__u8   anomalies;     /* enum em_anomaly */
	__u8   l4_parsed;     /* 1 if the transport header was read */
	__u8   _pad;
};

/* ---- helpers ---- */

static __always_inline int em_rc_is_error(int rc)
{
	return rc >= EM_PARSE_ERR_FIRST;
}

static __always_inline int em_is_vlan_tpid(__be16 proto)
{
	return proto == bpf_htons(EM_ETH_P_8021Q) || proto == bpf_htons(EM_ETH_P_8021AD) ||
	       proto == bpf_htons(EM_ETH_P_QINQ_9100);
}

static __always_inline int em_tcp_flags_bad(__u8 f)
{
	/* NULL scan */
	if ((f & (EM_TCP_FIN | EM_TCP_SYN | EM_TCP_RST | EM_TCP_PSH | EM_TCP_ACK | EM_TCP_URG)) == 0)
		return 1;
	if ((f & (EM_TCP_SYN | EM_TCP_FIN)) == (EM_TCP_SYN | EM_TCP_FIN))
		return 1;
	if ((f & (EM_TCP_SYN | EM_TCP_RST)) == (EM_TCP_SYN | EM_TCP_RST))
		return 1;
	/* Every segment after the initial SYN carries ACK; RST without ACK is
	 * legal. Anything else without ACK (FIN scan, XMAS, bare PSH/URG) is not
	 * produced by a conforming stack. */
	if (!(f & (EM_TCP_ACK | EM_TCP_SYN | EM_TCP_RST)))
		return 1;
	return 0;
}

static __always_inline int em_ipv6_is_ext(__u8 nh)
{
	return nh == EM_IPPROTO_HOPOPTS || nh == EM_IPPROTO_ROUTING ||
	       nh == EM_IPPROTO_FRAGMENT || nh == EM_IPPROTO_DSTOPTS ||
	       nh == EM_IPPROTO_AH;
}

/* ---- L2 ---- */

static __always_inline int em_parse_l2(void **pos, void *data_end, struct em_pkt *p)
{
	struct em_hdr_eth *eth = *pos;
	__be16 proto;

	if ((void *)(eth + 1) > data_end)
		return EM_PARSE_ERR_ETH_TRUNC;
	proto = eth->proto;
	*pos = eth + 1;

#pragma unroll
	for (int i = 0; i < EM_MAX_VLAN_DEPTH; i++) {
		struct em_hdr_vlan *vh = *pos;

		if (!em_is_vlan_tpid(proto))
			break;
		if ((void *)(vh + 1) > data_end)
			return EM_PARSE_ERR_VLAN_TRUNC;
		p->vlan_id[i] = bpf_ntohs(vh->tci) & 0x0FFF;
		p->vlan_depth = i + 1;
		proto = vh->proto;
		*pos = vh + 1;
	}

	p->eth_proto = proto;
	if (em_is_vlan_tpid(proto))
		return EM_PARSE_UNSUP_VLAN_DEPTH;
	return EM_PARSE_OK;
}

/* ---- L3 ---- */

static __always_inline int em_parse_ipv4(void **pos, void *data_end, struct em_pkt *p)
{
	struct em_hdr_ipv4 *iph = *pos;
	__u32 hlen, tot, frag;

	if ((void *)(iph + 1) > data_end)
		return EM_PARSE_ERR_IPV4_TRUNC;
	if ((iph->ver_ihl >> 4) != 4)
		return EM_PARSE_ERR_IPV4_VERSION;

	/* Masking bounds hlen to [0, 60] for the verifier; then enforce >= 20. */
	hlen = (__u32)(iph->ver_ihl & 0x0F) * 4;
	if (hlen < sizeof(*iph))
		return EM_PARSE_ERR_IPV4_IHL;
	if ((void *)iph + hlen > data_end)
		return EM_PARSE_ERR_IPV4_TRUNC;

	tot = em_ntohs_bounded(iph->tot_len);
	/* Trailing bytes after tot_len are legal (Ethernet minimum-size padding);
	 * a tot_len pointing past the end of the frame is not. */
	if (tot < hlen || (void *)iph + tot > data_end)
		return EM_PARSE_ERR_IPV4_TOTLEN;

	p->l3 = EM_L3_IPV4;
	p->saddr.v4 = iph->saddr;
	p->daddr.v4 = iph->daddr;
	p->ttl = iph->ttl;
	p->l4_proto = iph->protocol;
	p->l4_len = tot - hlen;
	if (hlen > sizeof(*iph))
		p->anomalies |= EM_ANOM_IPV4_OPTIONS;
	if (iph->saddr == iph->daddr)
		p->anomalies |= EM_ANOM_LAND;
	if (iph->ttl == 0)
		p->anomalies |= EM_ANOM_TTL_ZERO;

	frag = bpf_ntohs(iph->frag_off);
	if (frag & EM_IPV4_FRAG_OFFSET)
		p->frag = EM_FRAG_LATER;
	else if (frag & EM_IPV4_FRAG_MF)
		p->frag = EM_FRAG_FIRST;

	*pos = (void *)iph + hlen;
	return EM_PARSE_OK;
}

static __always_inline int em_parse_ipv6(void **pos, void *data_end, struct em_pkt *p)
{
	struct em_hdr_ipv6 *ip6 = *pos;
	__u32 plen, off = 0;
	void *base;
	__u8 nh;

	if ((void *)(ip6 + 1) > data_end)
		return EM_PARSE_ERR_IPV6_TRUNC;
	if ((bpf_ntohl(ip6->ver_tc_flow) >> 28) != 6)
		return EM_PARSE_ERR_IPV6_VERSION;

	plen = em_ntohs_bounded(ip6->payload_len);
	/* payload_len == 0 is only legal with a Jumbo Payload option (RFC 2675),
	 * which cannot occur on a <64 KiB linear XDP buffer. */
	if (plen == 0 || (void *)(ip6 + 1) + plen > data_end)
		return EM_PARSE_ERR_IPV6_PLEN;

	p->l3 = EM_L3_IPV6;
	__builtin_memcpy(p->saddr.v6, ip6->saddr, sizeof(p->saddr.v6));
	__builtin_memcpy(p->daddr.v6, ip6->daddr, sizeof(p->daddr.v6));
	p->ttl = ip6->hop_limit;
	if (p->saddr.v6[0] == p->daddr.v6[0] && p->saddr.v6[1] == p->daddr.v6[1] &&
	    p->saddr.v6[2] == p->daddr.v6[2] && p->saddr.v6[3] == p->daddr.v6[3])
		p->anomalies |= EM_ANOM_LAND;
	if (ip6->hop_limit == 0)
		p->anomalies |= EM_ANOM_TTL_ZERO;

	nh = ip6->nexthdr;
	base = ip6 + 1;

	/*
	 * The chain is walked with a scalar offset from the end of the fixed
	 * header rather than by advancing a packet pointer. At the top of each
	 * iteration the offset is re-bounded with a mask that is a no-op at
	 * runtime (at most EM_IPV6_MAX_EXT * 2048 bytes < EM_IPV6_EXT_OFF_MASK),
	 * so every iteration starts from an identical verifier state and path
	 * pruning works. Advancing a pointer instead gives each unrolled
	 * iteration a different pointer range and the verified instruction count
	 * grows geometrically with EM_IPV6_MAX_EXT.
	 *
	 * Every extension header is at least 8 bytes (HBH/DST/RH: (hdrlen+1)*8,
	 * AH: (hdrlen+2)*4, fragment: 8), so an 8-byte bounds check covers every
	 * field read here.
	 */
#pragma unroll
	for (int i = 0; i < EM_IPV6_MAX_EXT; i++) {
		struct em_hdr_ipv6_ext *eh;

		if (!em_ipv6_is_ext(nh))
			break;
		off = em_opaque(off) & EM_IPV6_EXT_OFF_MASK;
		eh = base + off;
		if ((void *)eh + 8 > data_end)
			return EM_PARSE_ERR_IPV6_EXT_TRUNC;
		p->n_ext++;

		if (nh == EM_IPPROTO_FRAGMENT) {
			struct em_hdr_ipv6_frag *fh = (void *)eh;
			__u16 fo = bpf_ntohs(fh->frag_off);

			nh = fh->nexthdr;
			off += sizeof(*fh);
			if (fo & EM_IPV6_FRAG_OFFSET) {
				/* Non-first fragment: the rest is opaque payload. */
				p->frag = EM_FRAG_LATER;
				break;
			}
			/* Offset 0 without M is an atomic fragment (RFC 6946):
			 * not actually fragmented. */
			if (fo & EM_IPV6_FRAG_MF)
				p->frag = EM_FRAG_FIRST;
			continue;
		}

		/* hdrlen is a u8: len <= 2048 (8-octet units) or 1028 (AH). */
		if (nh == EM_IPPROTO_AH)
			off += ((__u32)eh->hdrlen + 2) * 4;
		else
			off += ((__u32)eh->hdrlen + 1) * 8;
		nh = eh->nexthdr;
	}

	off = em_opaque(off) & EM_IPV6_EXT_OFF_MASK;
	p->l4_proto = nh;
	/* plen was checked against data_end above, so off <= plen also proves the
	 * whole chain lies inside the frame. */
	if (off > plen)
		return EM_PARSE_ERR_IPV6_EXT_TRUNC;
	*pos = base + off;
	p->l4_len = plen - off;
	if (p->frag != EM_FRAG_LATER && em_ipv6_is_ext(nh))
		return EM_PARSE_UNSUP_IPV6_EXT_DEPTH;
	return EM_PARSE_OK;
}

/* ---- L4 ---- */

static __always_inline int em_parse_l4(void **pos, void *data_end, struct em_pkt *p)
{
	/* Non-first fragments carry no transport header. */
	if (p->frag == EM_FRAG_LATER)
		return EM_PARSE_OK;

	if (p->l4_proto == EM_IPPROTO_TCP) {
		struct em_hdr_tcp *th = *pos;
		__u32 doff;

		if ((void *)(th + 1) > data_end || p->l4_len < sizeof(*th))
			/* RFC 1858: a first fragment too small to hold the
			 * transport header is an evasion technique. */
			return p->frag == EM_FRAG_FIRST ? EM_PARSE_ERR_FRAG_TINY
							: EM_PARSE_ERR_TCP_TRUNC;
		doff = (__u32)(th->doff_res >> 4) * 4;
		if (doff < sizeof(*th) || doff > p->l4_len)
			return EM_PARSE_ERR_TCP_DOFF;
		p->sport = th->source;
		p->dport = th->dest;
		p->tcp_flags = th->flags;
		if (em_tcp_flags_bad(th->flags))
			p->anomalies |= EM_ANOM_TCP_BAD_FLAGS;
		if (th->source == 0 || th->dest == 0)
			p->anomalies |= EM_ANOM_PORT_ZERO;
		p->l4_parsed = 1;
		return EM_PARSE_OK;
	}

	if (p->l4_proto == EM_IPPROTO_UDP) {
		struct em_hdr_udp *uh = *pos;
		__u32 ulen;

		if ((void *)(uh + 1) > data_end || p->l4_len < sizeof(*uh))
			return p->frag == EM_FRAG_FIRST ? EM_PARSE_ERR_FRAG_TINY
							: EM_PARSE_ERR_UDP_TRUNC;
		ulen = bpf_ntohs(uh->len);
		if (ulen < sizeof(*uh))
			return EM_PARSE_ERR_UDP_LEN;
		/* For a first fragment, len describes the reassembled datagram. */
		if (p->frag == EM_FRAG_NONE) {
			if (ulen > p->l4_len)
				return EM_PARSE_ERR_UDP_LEN;
			if (ulen < p->l4_len)
				p->anomalies |= EM_ANOM_UDP_LEN_MISMATCH;
		}
		p->sport = uh->source;
		p->dport = uh->dest;
		if (uh->source == 0 || uh->dest == 0)
			p->anomalies |= EM_ANOM_PORT_ZERO;
		p->l4_parsed = 1;
		return EM_PARSE_OK;
	}

	if ((p->l4_proto == EM_IPPROTO_ICMP && p->l3 == EM_L3_IPV4) ||
	    (p->l4_proto == EM_IPPROTO_ICMPV6 && p->l3 == EM_L3_IPV6)) {
		struct em_hdr_icmp *ih = *pos;

		if ((void *)(ih + 1) > data_end || p->l4_len < sizeof(*ih))
			return p->frag == EM_FRAG_FIRST ? EM_PARSE_ERR_FRAG_TINY
							: EM_PARSE_ERR_ICMP_TRUNC;
		p->icmp_type = ih->type;
		p->icmp_code = ih->code;
		p->l4_parsed = 1;
		return EM_PARSE_OK;
	}

	/* Other transports (GRE, ESP, SCTP, ICMPv4-in-IPv6, ...) are counted as
	 * L4_OTHER and not inspected. */
	return EM_PARSE_OK;
}

/*
 * Parse a frame. Returns enum em_parse_rc; *p is filled as far as parsing got
 * (e.g. p->l3 is set even if the TCP header turned out truncated). *p must be
 * zero-initialised by the caller.
 */
static __always_inline int em_parse_packet(void *data, void *data_end, struct em_pkt *p)
{
	void *pos = data;
	int rc;

	rc = em_parse_l2(&pos, data_end, p);
	if (rc != EM_PARSE_OK)
		return rc;

	if (p->eth_proto == bpf_htons(EM_ETH_P_IPV4))
		rc = em_parse_ipv4(&pos, data_end, p);
	else if (p->eth_proto == bpf_htons(EM_ETH_P_IPV6))
		rc = em_parse_ipv6(&pos, data_end, p);
	else
		return EM_PARSE_NOT_IP;
	if (rc != EM_PARSE_OK)
		return rc;

	return em_parse_l4(&pos, data_end, p);
}

#endif /* EM_PARSERS_H */
