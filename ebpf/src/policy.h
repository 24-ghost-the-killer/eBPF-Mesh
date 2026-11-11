/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Filtering steps 2-8 of the pipeline (spec section 5.1):
 *   local traffic, bogon sources, asset lookup, allowlist, blocklist, allowed
 *   services, fragments, per-source token bucket, SYN-cookie verification.
 */
#ifndef XS_POLICY_H
#define XS_POLICY_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "abi.h"
#include "maps.h"
#include "parse.h"
#include "syncookie.h"

/* ---- step 2: traffic for the PoP itself ---------------------------------- */

static __always_inline int xs_ip6_is_zero(const __u8 *a)
{
	const __u32 *w = (const __u32 *)a;

	return (w[0] | w[1] | w[2] | w[3]) == 0;
}

static __always_inline int xs_ip6_eq(const __u8 *a, const __u8 *b)
{
	const __u32 *x = (const __u32 *)a, *y = (const __u32 *)b;

	return ((x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]) | (x[3] ^ y[3])) == 0;
}

/*
 * True for packets addressed to the PoP itself: its unicast IPv4/IPv6
 * address, and IPv6 neighbour discovery (RS/RA/NS/NA/redirect) sent to
 * link-local or link-scope multicast addresses. Must run before the bogon
 * filter: ND uses link-local sources.
 */
static __always_inline int xs_is_local(const struct xs_pkt *pkt,
				       const struct xs_cfg *cfg)
{
	const __u8 *d = pkt->dst6.in6_u.u6_addr8;

	if (pkt->l3_proto == ETH_P_IP)
		return cfg && cfg->pop_ip4 && pkt->dst4 == cfg->pop_ip4;

	if (cfg && !xs_ip6_is_zero(cfg->pop_ip6) && xs_ip6_eq(d, cfg->pop_ip6))
		return 1;

	/* RS, RA, NS, NA, redirect to fe80::/10 or ff02::/16. icmp_type is only
	 * set when the ICMPv6 header was parsed (not for later fragments). */
	return pkt->l4_proto == IPPROTO_ICMPV6 && pkt->frag == XS_FRAG_NONE &&
	       pkt->icmp_type >= 133 && pkt->icmp_type <= 137 &&
	       ((d[0] == 0xfe && (d[1] & 0xc0) == 0x80) || (d[0] == 0xff && d[1] == 0x02));
}

/* ---- step 3: bogon sources ----------------------------------------------- */

static __always_inline int xs_bogon4(__be32 addr)
{
	__u32 a = bpf_ntohl(addr);

	return (a >> 24) == 0 ||                     /* 0.0.0.0/8 */
	       (a >> 24) == 10 ||                    /* 10.0.0.0/8 */
	       (a & 0xffc00000) == 0x64400000 ||     /* 100.64.0.0/10 */
	       (a >> 24) == 127 ||                   /* 127.0.0.0/8 */
	       (a & 0xffff0000) == 0xa9fe0000 ||     /* 169.254.0.0/16 */
	       (a & 0xfff00000) == 0xac100000 ||     /* 172.16.0.0/12 */
	       (a & 0xffff0000) == 0xc0a80000 ||     /* 192.168.0.0/16 */
	       (a >> 28) >= 0xe;                     /* 224/4, 240/4 */
}

static __always_inline int xs_bogon6(const __u8 *a)
{
	const __u32 *w = (const __u32 *)a;

	if ((w[0] | w[1]) == 0) {
		if (w[2] == 0 && (w[3] == 0 || w[3] == bpf_htonl(1)))
			return 1;                    /* ::, ::1 */
		if (w[2] == bpf_htonl(0xffff))
			return 1;                    /* ::ffff:0:0/96 */
	}
	return (a[0] & 0xfe) == 0xfc ||              /* fc00::/7 */
	       (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) || /* fe80::/10 */
	       a[0] == 0xff;                         /* ff00::/8 */
}

static __always_inline int xs_is_bogon(const struct xs_pkt *pkt)
{
	if (pkt->l3_proto == ETH_P_IP)
		return xs_bogon4(pkt->src4);
	return xs_bogon6(pkt->src6.in6_u.u6_addr8);
}

/* ---- step 4: tenant (asset) lookup ---------------------------------------- */

static __always_inline const struct xs_asset *xs_lookup_asset(const struct xs_pkt *pkt)
{
	if (pkt->l3_proto == ETH_P_IP) {
		struct xs_tenant_key k = { .prefixlen = 32, .addr = pkt->dst4 };

		return bpf_map_lookup_elem(&xs_tenants, &k);
	} else {
		struct xs_tenant6_key k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, &pkt->dst6, 16);
		return bpf_map_lookup_elem(&xs_tenants6, &k);
	}
}

/* ---- steps 5-6: allow and block lists ----------------------------------- */

/* Allow: expires 0 = permanent. Block: expires 0 is never active (a block
 * without a TTL is a bug; failing open is the safe direction). */
static __always_inline int xs_rule_active(const struct xs_rule *r, __u64 now,
					  int is_allow)
{
	if (!r)
		return 0;
	if (r->expires_ns == 0)
		return is_allow;
	return r->expires_ns > now;
}

/* Looks up the tenant's rule, then the global (tenant 0) rule. */
static __always_inline int xs_rule_match(void *map4, void *map6,
					 const struct xs_pkt *pkt, __u32 tenant,
					 __u64 now, int is_allow)
{
	if (pkt->l3_proto == ETH_P_IP) {
		struct xs_src_key k = { .prefixlen = 64, .tenant = tenant,
					.src = pkt->src4 };

		if (xs_rule_active(bpf_map_lookup_elem(map4, &k), now, is_allow))
			return 1;
		if (tenant == XS_TENANT_GLOBAL)
			return 0;
		k.tenant = XS_TENANT_GLOBAL;
		return xs_rule_active(bpf_map_lookup_elem(map4, &k), now, is_allow);
	} else {
		struct xs_src6_key k = { .prefixlen = 32 + 128, .tenant = tenant };

		__builtin_memcpy(k.src, &pkt->src6, 16);
		if (xs_rule_active(bpf_map_lookup_elem(map6, &k), now, is_allow))
			return 1;
		if (tenant == XS_TENANT_GLOBAL)
			return 0;
		k.tenant = XS_TENANT_GLOBAL;
		return xs_rule_active(bpf_map_lookup_elem(map6, &k), now, is_allow);
	}
}

/* ---- step 7: allowed services -------------------------------------------- */

/*
 * ICMP error messages (destination unreachable incl. fragmentation needed,
 * time exceeded, parameter problem; ICMPv6 1-4 incl. packet too big) belong
 * to traffic the origin itself sent. Dropping them breaks path MTU discovery,
 * so they bypass the services list (blocklist and rate limit still apply).
 */
static __always_inline int xs_icmp_error(const struct xs_pkt *pkt)
{
	if (pkt->l3_proto == ETH_P_IP && pkt->l4_proto == IPPROTO_ICMP)
		return pkt->icmp_type == 3 || pkt->icmp_type == 11 ||
		       pkt->icmp_type == 12;
	if (pkt->l3_proto == ETH_P_IPV6 && pkt->l4_proto == IPPROTO_ICMPV6)
		return pkt->icmp_type >= 1 && pkt->icmp_type <= 4;
	return 0;
}

static __always_inline int xs_service_allowed(const struct xs_pkt *pkt,
					      __u32 asset)
{
	struct xs_svc_key k = { .asset = asset, .proto = pkt->l4_proto };

	if (xs_icmp_error(pkt))
		return 1;

	if (pkt->l4_proto == IPPROTO_TCP || pkt->l4_proto == IPPROTO_UDP) {
		k.port = pkt->dport;
		if (bpf_map_lookup_elem(&xs_services, &k))
			return 1;
		k.port = 0; /* whole protocol allowed? */
	}
	return bpf_map_lookup_elem(&xs_services, &k) != NULL;
}

/* ---- step 8: per-source token bucket --------------------------------------
 * tokens are kept in units of 1e-9 packet so refill needs no division on the
 * common path: refill = elapsed_ns * pps. The bucket is shared by all CPUs;
 * concurrent updates can lose a few tokens, which only makes it stricter or
 * looser by a handful of packets. */
static __always_inline int xs_ratelimit_ok(const struct xs_policy *pol,
					   const struct xs_pkt *pkt,
					   __u32 tenant, __u64 now)
{
	struct xs_addr_key k = { .tenant = tenant };
	__u64 rate = pol->pps_per_src;
	__u64 cap, tokens, elapsed;
	struct xs_rl *b;

	if (!rate)
		return 1;
	cap = (__u64)(pol->burst ? pol->burst : pol->pps_per_src) * XS_NSEC;
	xs_addr_key_from_pkt(&k, pkt, XS_RL_V6_PREFIX);

	b = bpf_map_lookup_elem(&xs_rl, &k);
	if (!b) {
		struct xs_rl nb = { .tokens = cap - XS_NSEC, .last_ns = now };

		bpf_map_update_elem(&xs_rl, &k, &nb, BPF_NOEXIST);
		return 1;
	}
	elapsed = now > b->last_ns ? now - b->last_ns : 0;
	tokens = b->tokens;
	if (elapsed >= cap / rate) {
		tokens = cap; /* idle long enough to refill completely */
	} else {
		tokens += elapsed * rate; /* < cap, cannot overflow */
		if (tokens > cap)
			tokens = cap;
	}
	b->last_ns = now;
	if (tokens < XS_NSEC) {
		b->tokens = tokens;
		return 0;
	}
	b->tokens = tokens - XS_NSEC;
	return 1;
}

/* ---- steps 5-8 ------------------------------------------------------------ */

/*
 * Applies the tenant policy. Returns the verdict; *tx is set when the frame
 * was rewritten into a SYN challenge. Never rewrites unless mitigating.
 */
static __always_inline __u32 xs_policy_verdict(struct xdp_md *ctx,
					       const struct xs_pkt *pkt,
					       const struct xs_cfg *cfg,
					       const struct xs_policy *pol,
					       __u32 tenant, __u32 asset,
					       int later_frag, __u32 pkt_len,
					       int mitigate, int *tx)
{
	__u64 now = bpf_ktime_get_boot_ns();

	if (xs_rule_match(&xs_allow, &xs_allow6, pkt, tenant, now, 1))
		return XS_V_PASS_ALLOW;
	if (xs_rule_match(&xs_block, &xs_block6, pkt, tenant, now, 0))
		return XS_V_DROP_BLOCK;

	if (later_frag) {
		if (!(pol->flags & XS_P_ALLOW_FRAG))
			return XS_V_DROP_FRAGMENT;
	} else if ((pol->flags & XS_P_SERVICES) && !xs_service_allowed(pkt, asset)) {
		return XS_V_DROP_SERVICE;
	}

	if (!xs_ratelimit_ok(pol, pkt, tenant, now))
		return XS_V_DROP_RATELIMIT;

	if (later_frag)
		return XS_V_FRAGMENT;
	if ((pol->flags & XS_P_SYNCOOKIE) && pkt->l4_proto == IPPROTO_TCP &&
	    pkt->frag == XS_FRAG_NONE)
		return xs_syncookie(ctx, pkt, cfg, tenant, now, pkt_len, mitigate, tx);
	return XS_V_PASS;
}

/* xs_policy_eval() return value: verdict, plus this bit when the frame was
 * rewritten into a SYN challenge (send with XDP_TX). */
#define XS_EVAL_TX (1 << 16)
#define XS_EVAL_LATER_FRAG (1 << 0)
#define XS_EVAL_MITIGATE (1 << 1)

/*
 * Steps 5-8 for asset a. A global (non-inlined) function: the verifier checks
 * it once with unknown inputs instead of once per parser path of the caller.
 */
__attribute__((noinline)) int xs_policy_eval(struct xdp_md *ctx,
					     struct xs_pkt *pkt,
					     struct xs_asset *a, __u32 pkt_len,
					     __u32 eval_flags)
{
	__u32 zero = 0, verdict;
	const struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);
	int tx = 0;

	if (!ctx || !pkt || !a)
		return XS_V_PASS;
	verdict = xs_policy_verdict(ctx, pkt, cfg, &a->policy, a->tenant, a->asset,
				    eval_flags & XS_EVAL_LATER_FRAG, pkt_len,
				    !!(eval_flags & XS_EVAL_MITIGATE), &tx);
	return (int)(verdict | (tx ? XS_EVAL_TX : 0));
}

static __always_inline int xs_verdict_drops(__u32 v)
{
	switch (v) {
	case XS_V_DROP_MALFORMED:
	case XS_V_DROP_BOGON:
	case XS_V_DROP_BLOCK:
	case XS_V_DROP_SERVICE:
	case XS_V_DROP_FRAGMENT:
	case XS_V_DROP_RATELIMIT:
	case XS_V_SYN_VERIFIED: /* the RST is consumed by the PoP */
	case XS_V_DROP_UNVERIFIED:
		return 1;
	default:
		return 0;
	}
}

#endif /* XS_POLICY_H */
