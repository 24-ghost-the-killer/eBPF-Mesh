// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Sentinel-Edge XDP program.
 *
 * Phase 1 pipeline:
 *   1. parse; malformed -> XDP_DROP
 *   2. non-IP (ARP, LLDP, ...) -> XDP_PASS (the PoP needs ARP/ND for BGP)
 *   3. non-first fragments -> XDP_PASS (policy for them arrives in phase 2)
 *   4. everything else -> XDP_PASS
 * Every verdict is counted per (tenant, verdict) in xs_stats. With
 * XS_CFG_F_OBSERVE set, drops are counted but the packet is passed.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "abi.h"
#include "maps.h"
#include "parse.h"

static __always_inline void xs_count(__u32 tenant, __u32 verdict, __u64 bytes)
{
	struct xs_stats_key key = { .tenant = tenant, .verdict = verdict };
	struct xs_stats_val *val;

	val = bpf_map_lookup_elem(&xs_stats, &key);
	if (!val) {
		struct xs_stats_val zero = {};

		/* Racing CPUs may both insert; BPF_NOEXIST makes that harmless. */
		bpf_map_update_elem(&xs_stats, &key, &zero, BPF_NOEXIST);
		val = bpf_map_lookup_elem(&xs_stats, &key);
		if (!val)
			return; /* map full: nothing sane to do on the fast path */
	}
	/* Per-CPU value: no atomics needed. */
	val->pkts++;
	val->bytes += bytes;
}

static __always_inline __u32 xs_cfg_flags(void)
{
	__u32 zero = 0;
	struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);

	return cfg ? cfg->flags : 0;
}

SEC("xdp")
int xs_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 pkt_len = data_end - data;
	struct xs_pkt pkt = {};
	__u32 verdict;
	int action;

	switch (xs_parse(data, data_end, pkt_len, &pkt)) {
	case XS_P_OK:
		verdict = XS_V_PASS;
		action = XDP_PASS;
		break;
	case XS_P_NON_IP:
		verdict = XS_V_PASS_NON_IP;
		action = XDP_PASS;
		break;
	case XS_P_FRAGMENT:
		verdict = XS_V_FRAGMENT;
		action = XDP_PASS;
		break;
	default:
		verdict = XS_V_DROP_MALFORMED;
		action = XDP_DROP;
		break;
	}

	xs_count(XS_TENANT_GLOBAL, verdict, pkt_len);

	if (action == XDP_DROP && (xs_cfg_flags() & XS_CFG_F_OBSERVE))
		action = XDP_PASS;
	return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
