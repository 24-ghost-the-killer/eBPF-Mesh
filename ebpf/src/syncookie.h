/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * SYN-cookie source verification (ADR 0009).
 *
 *   client                      XDP (PoP)                      origin
 *   SYN(isn) ───────────────►  unverified: XDP_TX SYN-ACK
 *            ◄───────────────  (seq=h>>32, ack=cookie != isn+1)
 *   RST(seq=cookie) ────────►  cookie valid: xs_verified[src] = now+ttl, drop
 *   SYN(isn) (retransmit) ──►  verified: pass ───────────────► normal handshake
 *
 * A client in SYN-SENT that receives an unacceptable ACK sends RST with
 * seq = SEG.ACK and keeps its connection attempt (RFC 793; Linux even
 * retransmits the SYN almost immediately). Spoofed sources never answer, so
 * the origin never sees their SYNs.
 *
 * Packet rewriting rules: bpf_xdp_adjust_tail first, then re-derive data and
 * data_end and bounds-check again before any write.
 */
#ifndef XS_SYNCOOKIE_H
#define XS_SYNCOOKIE_H

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
#include "cookie.h"

#define XS_NSEC 1000000000ULL
/* Largest L4 offset the parser can produce: 14 + 8 + 40 + 4 * 2048. */
#define XS_MAX_L4_OFF 8256
#define XS_TCP_FIN 0x01
#define XS_TCP_SYN 0x02
#define XS_TCP_RST 0x04
#define XS_TCP_ACK 0x10

static __always_inline __u16 xs_csum_fold(__u64 sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

/* One's-complement sum of n 16-bit words (raw memory order). */
static __always_inline __u64 xs_csum_words(const __u16 *p, int n)
{
	__u64 sum = 0;

#pragma unroll
	for (int i = 0; i < n; i++)
		sum += p[i];
	return sum;
}

static __always_inline __u64 xs_csum_be32(__be32 v)
{
	return (v & 0xffff) + (v >> 16);
}

/* IPv4 as ::ffff:a.b.c.d, IPv6 masked to v6_prefix (64 or 128) bits. */
static __always_inline void xs_addr_key_from_pkt(struct xs_addr_key *k,
						 const struct xs_pkt *pkt,
						 int v6_prefix)
{
	if (pkt->l3_proto == ETH_P_IP) {
		__builtin_memset(k->addr, 0, 10);
		k->addr[10] = 0xff;
		k->addr[11] = 0xff;
		__builtin_memcpy(&k->addr[12], &pkt->src4, 4);
		return;
	}
	__builtin_memcpy(k->addr, &pkt->src6, 16);
	if (v6_prefix == 64)
		__builtin_memset(&k->addr[8], 0, 8);
}

/* Only plain headers are challenged: no IPv4 options, no IPv6 extension
 * headers, no fragments. Everything else from unverified sources is dropped. */
static __always_inline int xs_challengeable(const struct xs_pkt *pkt)
{
	if (pkt->frag != XS_FRAG_NONE)
		return 0;
	if (pkt->l3_proto == ETH_P_IP)
		return pkt->l4_off == pkt->l3_off + sizeof(struct iphdr);
	return pkt->l4_off == pkt->l3_off + sizeof(struct ipv6hdr);
}

static __always_inline __u64 xs_challenge_hash(const struct xs_cfg *cfg,
					       const struct xs_pkt *pkt,
					       __u32 slot)
{
	if (pkt->l3_proto == ETH_P_IP)
		return xs_cookie_hash4(cfg->cookie_key, pkt->src4, pkt->dst4,
				       pkt->sport, pkt->dport, slot);
	return xs_cookie_hash6(cfg->cookie_key, pkt->src6.in6_u.u6_addr8,
			       pkt->dst6.in6_u.u6_addr8, pkt->sport, pkt->dport,
			       slot);
}

static __always_inline void xs_fill_synack_tcp(struct tcphdr *th,
					       const struct xs_pkt *pkt,
					       __u32 seq, __u32 ack)
{
	th->source = pkt->dport;
	th->dest = pkt->sport;
	th->seq = bpf_htonl(seq);
	th->ack_seq = bpf_htonl(ack);
	((__u8 *)th)[12] = 5 << 4;                    /* doff 5, no options */
	((__u8 *)th)[13] = XS_TCP_SYN | XS_TCP_ACK;
	th->window = bpf_htons(XS_SYNACK_WINDOW);
	th->check = 0;
	th->urg_ptr = 0;
}

/*
 * Turn the SYN in ctx into the challenge SYN-ACK in place. pkt_len is the
 * current frame length. Returns 0 on success (caller returns XDP_TX).
 */
static __always_inline int xs_build_synack(struct xdp_md *ctx,
					   const struct xs_pkt *pkt,
					   __u32 pkt_len, __u32 seq, __u32 ack)
{
	__u32 new_len = pkt->l4_off + sizeof(struct tcphdr);
	int delta = (int)new_len - (int)pkt_len;
	void *data, *data_end;
	struct ethhdr *eth;
	__u8 mac[ETH_ALEN];

	if (delta > 0)
		return -1;
	/* Drop TCP options and any Ethernet padding. */
	if (delta < 0 && bpf_xdp_adjust_tail(ctx, delta))
		return -1;

	/* adjust_tail invalidates every packet pointer: re-derive. */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;
	__builtin_memcpy(mac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, mac, ETH_ALEN);

	if (pkt->l3_proto == ETH_P_IP) {
		struct iphdr *ip = data + XS_BOUND(pkt->l3_off, 0x1f);
		struct tcphdr *th = (void *)(ip + 1);
		__u64 sum;

		if ((void *)(th + 1) > data_end)
			return -1;
		ip->tos = 0;
		ip->tot_len = bpf_htons(sizeof(*ip) + sizeof(*th));
		ip->id = 0;
		ip->frag_off = bpf_htons(0x4000); /* DF */
		ip->ttl = XS_SYNACK_TTL;
		ip->protocol = IPPROTO_TCP;
		ip->saddr = pkt->dst4;
		ip->daddr = pkt->src4;
		ip->check = 0;
		ip->check = xs_csum_fold(xs_csum_words((__u16 *)ip, 10));

		xs_fill_synack_tcp(th, pkt, seq, ack);
		sum = xs_csum_be32(pkt->dst4) + xs_csum_be32(pkt->src4) +
		      bpf_htons(IPPROTO_TCP) + bpf_htons(sizeof(*th)) +
		      xs_csum_words((__u16 *)th, 10);
		th->check = xs_csum_fold(sum);
		return 0;
	}

	{
		struct ipv6hdr *ip6 = data + XS_BOUND(pkt->l3_off, 0x1f);
		struct tcphdr *th = (void *)(ip6 + 1);
		__u64 sum;

		if ((void *)(th + 1) > data_end)
			return -1;
		*(__be32 *)ip6 = bpf_htonl(0x60000000); /* version, tc 0, flow 0 */
		ip6->payload_len = bpf_htons(sizeof(*th));
		ip6->nexthdr = IPPROTO_TCP;
		ip6->hop_limit = XS_SYNACK_TTL;
		__builtin_memcpy(&ip6->saddr, &pkt->dst6, 16);
		__builtin_memcpy(&ip6->daddr, &pkt->src6, 16);

		xs_fill_synack_tcp(th, pkt, seq, ack);
		sum = xs_csum_words((__u16 *)&ip6->saddr, 16) +
		      bpf_htons(sizeof(*th)) + bpf_htons(IPPROTO_TCP) +
		      xs_csum_words((__u16 *)th, 10);
		th->check = xs_csum_fold(sum);
		return 0;
	}
}

/*
 * SYN-cookie step for a TCP packet. Returns the verdict; sets *tx when the
 * packet has been rewritten into a challenge and must be sent with XDP_TX.
 * Challenges are only sent when mitigating.
 */
static __always_inline __u32 xs_syncookie(struct xdp_md *ctx,
					  const struct xs_pkt *pkt,
					  const struct xs_cfg *cfg,
					  __u32 tenant, __u64 now,
					  __u32 pkt_len, int mitigate, int *tx)
{
	struct xs_addr_key vk = { .tenant = tenant };
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct tcphdr *th;
	__u64 ttl, *exp;
	__u32 slot;
	__u8 flags = pkt->tcp_flags;

	/* No key configured: fail open rather than block everything. */
	if (!cfg || (cfg->cookie_key[0] == 0 && cfg->cookie_key[1] == 0))
		return XS_V_PASS;

	ttl = (__u64)(cfg->verify_ttl_s ? cfg->verify_ttl_s :
					  XS_VERIFY_TTL_DEFAULT_S) * XS_NSEC;
	xs_addr_key_from_pkt(&vk, pkt, 128);
	exp = bpf_map_lookup_elem(&xs_verified, &vk);
	if (exp && *exp > now) {
		/* Keep active sources verified; refresh at most every ttl/2. */
		if (*exp - now < ttl / 2)
			*exp = now + ttl;
		return XS_V_PASS;
	}

	if (pkt->l4_off > XS_MAX_L4_OFF)
		return XS_V_DROP_UNVERIFIED;
	th = data + XS_BOUND(pkt->l4_off, 0x3fff);
	if ((void *)(th + 1) > data_end)
		return XS_V_DROP_UNVERIFIED;
	slot = xs_cookie_slot(now);

	if ((flags & (XS_TCP_SYN | XS_TCP_ACK | XS_TCP_RST)) == XS_TCP_SYN) {
		__u64 h;

		if (!mitigate)
			return XS_V_TX_SYN_CHALLENGE; /* observe: count only */
		if (!xs_challengeable(pkt))
			return XS_V_DROP_UNVERIFIED;
		h = xs_challenge_hash(cfg, pkt, slot);
		if (xs_build_synack(ctx, pkt, pkt_len, xs_challenge_seq(h),
				    xs_challenge_ack(h, bpf_ntohl(th->seq))))
			return XS_V_DROP_UNVERIFIED;
		*tx = 1;
		return XS_V_TX_SYN_CHALLENGE;
	}

	if ((flags & (XS_TCP_RST | XS_TCP_SYN)) == XS_TCP_RST) {
		__u32 rst_seq = bpf_ntohl(th->seq);

		if (xs_cookie_matches(xs_challenge_hash(cfg, pkt, slot), rst_seq) ||
		    xs_cookie_matches(xs_challenge_hash(cfg, pkt, slot - 1), rst_seq)) {
			__u64 until = now + ttl;

			bpf_map_update_elem(&xs_verified, &vk, &until, BPF_ANY);
			return XS_V_SYN_VERIFIED;
		}
	}
	return XS_V_DROP_UNVERIFIED;
}

#endif /* XS_SYNCOOKIE_H */
