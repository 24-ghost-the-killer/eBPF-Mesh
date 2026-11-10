/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * account.h - map a parse result onto counter slots.
 *
 * Pure functions over a struct em_stats (no helpers, no maps), so the same
 * code that runs in the XDP program is exercised by the host tests, which
 * check that each corpus frame increments exactly the expected slots.
 *
 * The stats block is per-CPU and XDP runs with migration disabled, so plain
 * (non-atomic) increments are correct and cheap.
 */
#ifndef EM_ACCOUNT_H
#define EM_ACCOUNT_H

#include "compat.h"
#include "abi.h"
#include "parsers.h"

static __always_inline void em_count(struct em_stats *st, __u32 id, __u64 len)
{
	/* Re-bound the index for the verifier; id is a constant at most call
	 * sites, so the check folds away there. */
	if (id >= EM_CNT_SLOTS)
		return;
	st->c[id].packets++;
	st->c[id].bytes += len;
}

/* Counters that depend only on the parser output. Exactly one parse-outcome
 * slot per frame, plus the classification slots documented in abi.h. */
static __always_inline void em_account_parse(struct em_stats *st, const struct em_pkt *p,
					     int rc, __u64 len)
{
	__u32 r = (__u32)rc;

	if (r < EM_PARSE_RC_MAX)
		em_count(st, EM_CNT_PARSE_BASE + r, len);

	if (p->vlan_depth == 1)
		em_count(st, EM_CNT_L2_VLAN1, len);
	else if (p->vlan_depth == 2)
		em_count(st, EM_CNT_L2_VLAN2, len);

	/* L3: the IP header itself was valid (p->l3 is only set after its
	 * checks), even if a later layer failed. */
	if (p->l3 == EM_L3_IPV4)
		em_count(st, EM_CNT_L3_IPV4, len);
	else if (p->l3 == EM_L3_IPV6)
		em_count(st, EM_CNT_L3_IPV6, len);
	else if (rc == EM_PARSE_NOT_IP)
		em_count(st, p->eth_proto == bpf_htons(EM_ETH_P_ARP) ? EM_CNT_L3_ARP
								      : EM_CNT_L3_OTHER, len);

	if (rc != EM_PARSE_OK || p->l3 == EM_L3_NONE)
		return;

	/* L4 */
	if (p->l4_proto == EM_IPPROTO_TCP)
		em_count(st, EM_CNT_L4_TCP, len);
	else if (p->l4_proto == EM_IPPROTO_UDP)
		em_count(st, EM_CNT_L4_UDP, len);
	else if (p->l4_proto == EM_IPPROTO_ICMP && p->l3 == EM_L3_IPV4)
		em_count(st, EM_CNT_L4_ICMP, len);
	else if (p->l4_proto == EM_IPPROTO_ICMPV6 && p->l3 == EM_L3_IPV6)
		em_count(st, EM_CNT_L4_ICMPV6, len);
	else
		em_count(st, EM_CNT_L4_OTHER, len);

	if (p->frag == EM_FRAG_FIRST)
		em_count(st, EM_CNT_FRAG_FIRST, len);
	else if (p->frag == EM_FRAG_LATER)
		em_count(st, EM_CNT_FRAG_LATER, len);
	if (p->n_ext)
		em_count(st, EM_CNT_IPV6_EXT, len);

	if (p->l4_parsed && p->l4_proto == EM_IPPROTO_TCP) {
		__u8 f = p->tcp_flags;

		if ((f & EM_TCP_SYN) && !(f & EM_TCP_ACK))
			em_count(st, EM_CNT_TCP_SYN, len);
		if ((f & EM_TCP_SYN) && (f & EM_TCP_ACK))
			em_count(st, EM_CNT_TCP_SYNACK, len);
		if ((f & (EM_TCP_ACK | EM_TCP_SYN | EM_TCP_FIN | EM_TCP_RST)) == EM_TCP_ACK)
			em_count(st, EM_CNT_TCP_ACK, len);
		if (f & EM_TCP_FIN)
			em_count(st, EM_CNT_TCP_FIN, len);
		if (f & EM_TCP_RST)
			em_count(st, EM_CNT_TCP_RST, len);
	}

	if (p->anomalies & EM_ANOM_IPV4_OPTIONS)
		em_count(st, EM_CNT_ANOM_IPV4_OPTIONS, len);
	if (p->anomalies & EM_ANOM_TCP_BAD_FLAGS)
		em_count(st, EM_CNT_ANOM_TCP_BAD_FLAGS, len);
	if (p->anomalies & EM_ANOM_UDP_LEN_MISMATCH)
		em_count(st, EM_CNT_ANOM_UDP_LEN_MISMATCH, len);
	if (p->anomalies & EM_ANOM_LAND)
		em_count(st, EM_CNT_ANOM_LAND, len);
	if (p->anomalies & EM_ANOM_TTL_ZERO)
		em_count(st, EM_CNT_ANOM_TTL_ZERO, len);
	if (p->anomalies & EM_ANOM_PORT_ZERO)
		em_count(st, EM_CNT_ANOM_PORT_ZERO, len);
}

#endif /* EM_ACCOUNT_H */
