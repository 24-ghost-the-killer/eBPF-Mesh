/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Tunnel delivery (ADR 0012).
 *
 * Forward: protected packets get an outer IPv4 header (src = PoP unicast IP,
 * dst = asset origin; protocol 4 for IPv4, 41 for IPv6) and leave with
 * XDP_TX towards the next-hop router. VLAN tags are kept.
 *
 * Return: origins send replies inside IPIP/6in4 to the anycast tunnel
 * endpoint. The nearest PoP checks that the outer source is the registered
 * origin of the inner source's asset, clamps the MSS of SYN(-ACK)s so client
 * packets fit the tunnel, strips the outer header and forwards the reply.
 *
 * Every bpf_xdp_adjust_head() is followed by re-deriving data/data_end and
 * bounds-checking again before any write.
 */
#ifndef XS_TUNNEL_H
#define XS_TUNNEL_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "abi.h"
#include "maps.h"
#include "parse.h"
#include "syncookie.h" /* xs_csum_fold, xs_csum_words */

#define XS_L2_MAX (ETH_HLEN + 4 * XS_MAX_VLAN_TAGS)

/* ---- L2 header save / restore (length is 14, 18 or 22) ------------------- */

static __always_inline int xs_l2_load(void *data, void *data_end, __u8 *buf,
				      __u16 len)
{
	switch (len) {
	case ETH_HLEN:
		if (data + ETH_HLEN > data_end)
			return -1;
		__builtin_memcpy(buf, data, ETH_HLEN);
		return 0;
	case ETH_HLEN + 4:
		if (data + ETH_HLEN + 4 > data_end)
			return -1;
		__builtin_memcpy(buf, data, ETH_HLEN + 4);
		return 0;
	case ETH_HLEN + 8:
		if (data + ETH_HLEN + 8 > data_end)
			return -1;
		__builtin_memcpy(buf, data, ETH_HLEN + 8);
		return 0;
	}
	return -1;
}

/* Writes the saved L2 header and sets the innermost ethertype. */
static __always_inline int xs_l2_store(void *data, void *data_end,
				       const __u8 *buf, __u16 len, __be16 proto)
{
	switch (len) {
	case ETH_HLEN:
		if (data + ETH_HLEN > data_end)
			return -1;
		__builtin_memcpy(data, buf, ETH_HLEN);
		*(__be16 *)(data + ETH_HLEN - 2) = proto;
		return 0;
	case ETH_HLEN + 4:
		if (data + ETH_HLEN + 4 > data_end)
			return -1;
		__builtin_memcpy(data, buf, ETH_HLEN + 4);
		*(__be16 *)(data + ETH_HLEN + 2) = proto;
		return 0;
	case ETH_HLEN + 8:
		if (data + ETH_HLEN + 8 > data_end)
			return -1;
		__builtin_memcpy(data, buf, ETH_HLEN + 8);
		*(__be16 *)(data + ETH_HLEN + 6) = proto;
		return 0;
	}
	return -1;
}

/* New source MAC = our NIC (the frame's destination); new destination = the
 * configured next hop, or the sender if none is configured. */
static __always_inline void xs_l2_route(__u8 *l2, const struct xs_cfg *cfg)
{
	const __u8 *nh = cfg->nexthop_mac;
	__u8 sender[ETH_ALEN];

	__builtin_memcpy(sender, l2 + ETH_ALEN, ETH_ALEN);
	__builtin_memcpy(l2 + ETH_ALEN, l2, ETH_ALEN);
	if (nh[0] | nh[1] | nh[2] | nh[3] | nh[4] | nh[5])
		__builtin_memcpy(l2, nh, ETH_ALEN);
	else
		__builtin_memcpy(l2, sender, ETH_ALEN);
}

static __always_inline __u32 xs_mtu(const struct xs_cfg *cfg)
{
	return cfg->uplink_mtu ? cfg->uplink_mtu : XS_DEFAULT_MTU;
}

/* ---- forward: encapsulate -------------------------------------------------- */

/*
 * Encapsulates the frame for asset a. Returns 0 (send with XDP_TX) or the
 * verdict explaining why it cannot be delivered. Global function (see
 * xs_policy_eval).
 */
__attribute__((noinline)) int xs_deliver(struct xdp_md *ctx, struct xs_pkt *pkt,
					 struct xs_asset *a)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	const struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);
	__u16 l2len;
	__u8 l2[XS_L2_MAX];
	struct iphdr *o;
	__u8 *inner;
	__u8 tos;

	if (!pkt || !a || !cfg || !cfg->pop_ip4 || !a->origin4)
		return XS_V_DROP_TUNNEL;
	if ((__u32)pkt->ip_len + XS_TUNNEL_OVERHEAD > xs_mtu(cfg))
		return XS_V_DROP_TOO_BIG;
	l2len = pkt->l3_off;
	if (xs_l2_load(data, data_end, l2, l2len))
		return XS_V_DROP_TUNNEL;

	/* Copy DSCP/ECN to the outer header (RFC 6040 normal mode). */
	inner = data + XS_BOUND(l2len, 0x1f);
	if ((void *)(inner + 2) > data_end)
		return XS_V_DROP_TUNNEL;
	tos = pkt->l3_proto == ETH_P_IP ? inner[1] :
					  (__u8)((inner[0] << 4) | (inner[1] >> 4));
	xs_l2_route(l2, cfg);

	if (bpf_xdp_adjust_head(ctx, -XS_TUNNEL_OVERHEAD))
		return XS_V_DROP_TUNNEL;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (xs_l2_store(data, data_end, l2, l2len, bpf_htons(ETH_P_IP)))
		return XS_V_DROP_TUNNEL;
	o = data + XS_BOUND(l2len, 0x1f);
	if ((void *)(o + 1) > data_end)
		return XS_V_DROP_TUNNEL;
	*(__u8 *)o = 0x45; /* version 4, IHL 5 */
	o->tos = tos;
	o->tot_len = bpf_htons(pkt->ip_len + XS_TUNNEL_OVERHEAD);
	o->id = 0;
	o->frag_off = bpf_htons(0x4000); /* DF: the outer packet is never fragmented */
	o->ttl = 64;
	o->protocol = pkt->l3_proto == ETH_P_IP ? IPPROTO_IPIP : IPPROTO_IPV6;
	o->saddr = cfg->pop_ip4;
	o->daddr = a->origin4;
	o->check = 0;
	o->check = xs_csum_fold(xs_csum_words((__u16 *)o, 10));
	return 0;
}

/* ---- return: MSS clamp, validate, decapsulate ---------------------------------- */

/* RFC 1624: HC' = ~(~HC + ~m + m'), all as big-endian 16-bit numbers. */
static __always_inline __u16 xs_csum16_replace(__u16 hc, __u16 m, __u16 m2)
{
	__u32 s = (__u16)~hc + (__u16)~m + m2;

	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/*
 * Lowers the MSS option of a SYN or SYN-ACK at tcp_off to mss_max and fixes
 * the TCP checksum incrementally. Returns 1 if the MSS was changed.
 *
 * Only an MSS that is the first option, optionally after up to 4 NOPs, is
 * clamped: that is where Linux, Windows and the BSDs put it. A general
 * option walk makes the verifier explore every combination of option
 * lengths (> 1M instructions); this is defence in depth anyway, since the
 * customer script sets the tunnel MTU so the origin advertises a fitting
 * MSS itself (ADR 0012).
 *
 * If NOPs put the MSS at an odd offset its value bytes sit in two checksum
 * words, which is the same as replacing the byte-swapped value.
 */
__attribute__((noinline)) int xs_mss_clamp(struct xdp_md *ctx, __u32 tcp_off,
					   __u32 mss_max)
{
	__u8 hdr[20], opt[8] = {}, val[2];
	__u16 mss, hc, m, m2;
	__u32 off = 0, sh;
	__u64 w;
	__be16 check;

	if (!ctx || tcp_off > XS_MAX_L4_OFF || mss_max > 0xffff)
		return 0;
	if (bpf_xdp_load_bytes(ctx, tcp_off, hdr, sizeof(hdr)))
		return 0;
	if (!(hdr[13] & XS_TCP_SYN) || (hdr[12] >> 4) <= 5)
		return 0;
	/* At least one option word is present; read a second if there is one. */
	if (bpf_xdp_load_bytes(ctx, tcp_off + sizeof(hdr), opt, 4))
		return 0;
	if ((hdr[12] >> 4) >= 7 &&
	    bpf_xdp_load_bytes(ctx, tcp_off + sizeof(hdr) + 4, &opt[4], 4))
		return 0;

	if (opt[0] == 1) {
		off = 1;
		if (opt[1] == 1) {
			off = 2;
			if (opt[2] == 1) {
				off = 3;
				if (opt[3] == 1)
					off = 4;
			}
		}
	}
	/*
	 * opt[] is zero beyond the options read, so a short header never
	 * matches kind 2 / length 4. The bytes are picked from one scalar with
	 * shifts: indexing opt[] with the variable off lets compilers build a
	 * stack pointer with OR (clang 18 does), which the verifier refuses.
	 */
	w = (__u64)opt[0] | (__u64)opt[1] << 8 | (__u64)opt[2] << 16 |
	    (__u64)opt[3] << 24 | (__u64)opt[4] << 32 | (__u64)opt[5] << 40 |
	    (__u64)opt[6] << 48 | (__u64)opt[7] << 56;
	sh = off * 8;
	if (((w >> sh) & 0xff) != 2 || ((w >> (sh + 8)) & 0xff) != 4)
		return 0;
	mss = (__u16)(((w >> (sh + 16)) & 0xff) << 8 | ((w >> (sh + 24)) & 0xff));
	if (mss <= mss_max)
		return 0;

	hc = ((__u16)hdr[16] << 8) | hdr[17];
	if (off & 1) { /* value bytes straddle two checksum words */
		m = (__u16)((mss & 0xff) << 8) | (mss >> 8);
		m2 = (__u16)((mss_max & 0xff) << 8) | (mss_max >> 8);
	} else {
		m = mss;
		m2 = mss_max;
	}
	val[0] = mss_max >> 8;
	val[1] = mss_max & 0xff;
	check = bpf_htons(xs_csum16_replace(hc, m, m2));
	if (bpf_xdp_store_bytes(ctx, tcp_off + sizeof(hdr) + off + 2, val, 2) ||
	    bpf_xdp_store_bytes(ctx, tcp_off + 16, &check, 2))
		return 0;
	return 1;
}

static __always_inline int xs_is_return(const struct xs_pkt *pkt,
					const struct xs_cfg *cfg)
{
	return cfg && cfg->tunnel_ep4 && pkt->l3_proto == ETH_P_IP &&
	       pkt->dst4 == cfg->tunnel_ep4;
}

/*
 * Handles a packet sent to the tunnel endpoint. Returns XS_V_TX_RETURN (frame
 * rewritten, send with XDP_TX) or XS_V_DROP_RETURN. *tenant is set to the
 * owner of the inner source when it is a valid asset. Global function.
 */
__attribute__((noinline)) int xs_return(struct xdp_md *ctx, struct xs_pkt *pkt,
					__u32 *tenant)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0, inner_off, tcp_off = 0, mss_max = 0;
	const struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);
	const struct xs_asset *a;
	__u16 l2len;
	__u8 l2[XS_L2_MAX];
	__be16 proto;

	if (!pkt || !tenant || !cfg || pkt->l3_off > XS_L2_MAX)
		return XS_V_DROP_RETURN;
	l2len = pkt->l3_off;
	inner_off = XS_BOUND(l2len, 0x1f) + sizeof(struct iphdr);

	/* Plain outer header only: no options, no fragments. */
	if (pkt->frag != XS_FRAG_NONE || pkt->l4_off != inner_off)
		return XS_V_DROP_RETURN;

	if (pkt->l4_proto == IPPROTO_IPIP) {
		struct iphdr *in = data + inner_off;
		struct xs_tenant_key k = { .prefixlen = 32 };
		__u32 ihl, len;

		if ((void *)(in + 1) > data_end || in->version != 4 || in->ihl < 5)
			return XS_V_DROP_RETURN;
		ihl = in->ihl * 4;
		len = bpf_ntohs(in->tot_len);
		if (len < ihl || len + sizeof(struct iphdr) > pkt->ip_len)
			return XS_V_DROP_RETURN;
		k.addr = in->saddr;
		a = bpf_map_lookup_elem(&xs_tenants, &k);
		if (!a || a->origin4 != pkt->src4)
			return XS_V_DROP_RETURN;
		if (in->protocol == IPPROTO_TCP &&
		    !(bpf_ntohs(in->frag_off) & (XS_IP4_OFFSET | XS_IP4_MF))) {
			tcp_off = inner_off + ihl;
			mss_max = xs_mtu(cfg) - 60; /* outer + IPv4 + TCP headers */
		}
		proto = bpf_htons(ETH_P_IP);
	} else if (pkt->l4_proto == IPPROTO_IPV6) {
		struct ipv6hdr *in6 = data + inner_off;
		struct xs_tenant6_key k = { .prefixlen = 128 };

		if ((void *)(in6 + 1) > data_end || in6->version != 6)
			return XS_V_DROP_RETURN;
		if (sizeof(*in6) + bpf_ntohs(in6->payload_len) + sizeof(struct iphdr) >
		    pkt->ip_len)
			return XS_V_DROP_RETURN;
		__builtin_memcpy(k.addr, &in6->saddr, 16);
		a = bpf_map_lookup_elem(&xs_tenants6, &k);
		if (!a || a->origin4 != pkt->src4)
			return XS_V_DROP_RETURN;
		if (in6->nexthdr == IPPROTO_TCP) {
			tcp_off = inner_off + sizeof(*in6);
			mss_max = xs_mtu(cfg) - 80; /* outer + IPv6 + TCP headers */
		}
		proto = bpf_htons(ETH_P_IPV6);
	} else {
		return XS_V_DROP_RETURN;
	}
	*tenant = a->tenant;
	if (tcp_off)
		xs_mss_clamp(ctx, tcp_off, mss_max);

	/* The clamp may have written to the packet: reload pointers. */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (xs_l2_load(data, data_end, l2, l2len))
		return XS_V_DROP_RETURN;
	xs_l2_route(l2, cfg);
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr)))
		return XS_V_DROP_RETURN;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (xs_l2_store(data, data_end, l2, l2len, proto))
		return XS_V_DROP_RETURN;
	return XS_V_TX_RETURN;
}

#endif /* XS_TUNNEL_H */
