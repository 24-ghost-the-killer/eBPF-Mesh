// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Sentinel-Edge XDP program.
 *
 * Pipeline (cheapest checks first):
 *   1. parse; malformed -> drop                         [global]
 *      non-IP (ARP, LLDP, ...) -> pass
 *   2. to the PoP itself (unicast IP, IPv6 ND) -> pass  [global]
 *   3. bogon source -> drop                              [global]
 *   4. tenant lookup                                     (phase 3; until then
 *                                                         one default policy)
 *   5. allowlist -> pass, skipping 6-8                   [policy]
 *   6. blocklist (unexpired) -> drop                     [policy]
 *   7. allowed services / fragments -> drop the rest     [policy]
 *   8. per-source token bucket; SYN-cookie verification  [policy]
 *
 * [global] drops obey only the XS_CFG_F_OBSERVE kill switch. [policy] drops
 * and challenges happen only when the policy has XS_P_MITIGATE (and the kill
 * switch is off); otherwise the verdict is counted and the packet passed.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "abi.h"
#include "maps.h"
#include "parse.h"
#include "policy.h"

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

SEC("xdp")
int xs_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 pkt_len = data_end - data;
	__u32 zero = 0, verdict, tenant = XS_TENANT_GLOBAL;
	const struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);
	int global_observe = cfg && (cfg->flags & XS_CFG_F_OBSERVE);
	struct xs_pkt pkt = {};
	int rc, action, tx = 0;

	rc = xs_parse(data, data_end, pkt_len, &pkt);
	if (rc == XS_P_MALFORMED) {
		verdict = XS_V_DROP_MALFORMED;
		action = global_observe ? XDP_PASS : XDP_DROP;
		goto out;
	}
	if (rc == XS_P_NON_IP) {
		verdict = XS_V_PASS_NON_IP;
		action = XDP_PASS;
		goto out;
	}
	if (xs_is_local(&pkt, cfg)) {
		verdict = XS_V_PASS_LOCAL;
		action = XDP_PASS;
		goto out;
	}
	if (xs_is_bogon(&pkt)) {
		verdict = XS_V_DROP_BOGON;
		action = global_observe ? XDP_PASS : XDP_DROP;
		goto out;
	}

	{
		/* Phase 2: one default policy, tenant 0, asset 0. */
		const struct xs_policy *pol = bpf_map_lookup_elem(&xs_policy, &zero);
		int mitigate;

		if (!pol) {
			verdict = XS_V_PASS;
			action = XDP_PASS;
			goto out;
		}
		mitigate = (pol->flags & XS_P_MITIGATE) && !global_observe;
		verdict = xs_policy_verdict(ctx, &pkt, cfg, pol, tenant, 0,
					    rc == XS_P_FRAGMENT, pkt_len,
					    mitigate, &tx);
		if (tx)
			action = XDP_TX;
		else
			action = mitigate && xs_verdict_drops(verdict) ? XDP_DROP :
									 XDP_PASS;
	}
out:
	/* Bytes counted as received, before any rewrite. */
	xs_count(tenant, verdict, pkt_len);
	return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
