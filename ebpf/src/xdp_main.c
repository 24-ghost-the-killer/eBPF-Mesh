// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Sentinel-Edge XDP program.
 *
 * Pipeline (cheapest checks first):
 *   1. parse; malformed -> drop                         [global]
 *      non-IP (ARP, LLDP, ...) -> pass to the kernel
 *   r. to the anycast tunnel endpoint: origin reply ->
 *      validate, clamp MSS, decapsulate, forward        (tunnel.h)
 *   2. to the PoP itself (unicast IP, IPv6 ND) -> pass  [global]
 *   3. bogon source -> drop                              [global]
 *   4. asset lookup on destination; none -> drop         [global]
 *   5. allowlist -> deliver, skipping 6-8                [policy]
 *   6. blocklist (unexpired) -> drop                     [policy]
 *   7. allowed services / fragments -> drop the rest     [policy]
 *   8. per-source token bucket; SYN-cookie verification  [policy]
 *  10. deliver: encapsulate to the asset's origin, XDP_TX
 *
 * [global] drops obey only the XS_CFG_F_OBSERVE kill switch. [policy] drops
 * and challenges happen only when the asset's policy has XS_P_MITIGATE (and
 * the kill switch is off). In observe mode the verdict is counted and the
 * packet is still delivered through the tunnel. (Step 9, sampling, arrives
 * with the agent in phase 4.)
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "abi.h"
#include "maps.h"
#include "parse.h"
#include "policy.h"
#include "tunnel.h"

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
	__u32 zero = 0, verdict, fail, tenant = XS_TENANT_GLOBAL;
	const struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);
	int global_observe = cfg && (cfg->flags & XS_CFG_F_OBSERVE);
	const struct xs_asset *a;
	struct xs_asset asset;
	struct xs_pkt pkt = {};
	int rc, action, eval;

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
	if (xs_is_return(&pkt, cfg)) {
		verdict = xs_return(ctx, &pkt, &tenant);
		if (verdict == XS_V_TX_RETURN)
			action = XDP_TX;
		else
			action = global_observe ? XDP_PASS : XDP_DROP;
		goto out;
	}
	if (xs_is_local(&pkt, cfg)) {
		verdict = XS_V_PASS_LOCAL;
		action = XDP_PASS;
		goto out;
	}

	a = xs_lookup_asset(&pkt);
	if (a) {
		asset = *a; /* stack copy for the global functions */
		tenant = asset.tenant;
	}

	if (xs_is_bogon(&pkt)) {
		verdict = XS_V_DROP_BOGON;
		if (!global_observe) {
			action = XDP_DROP;
			goto out;
		}
		if (!a) {
			action = XDP_PASS;
			goto out;
		}
		goto deliver; /* kill switch: count, but keep delivering */
	}
	if (!a) {
		verdict = XS_V_DROP_NO_TENANT;
		action = global_observe ? XDP_PASS : XDP_DROP;
		goto out;
	}

	eval = 0;
	if (rc == XS_P_FRAGMENT)
		eval |= XS_EVAL_LATER_FRAG;
	if ((asset.policy.flags & XS_P_MITIGATE) && !global_observe)
		eval |= XS_EVAL_MITIGATE;
	eval = xs_policy_eval(ctx, &pkt, &asset, pkt_len, eval);
	verdict = eval & 0xffff;
	if (eval & XS_EVAL_TX) {
		action = XDP_TX; /* SYN challenge back to the client */
		goto out;
	}
	if ((asset.policy.flags & XS_P_MITIGATE) && !global_observe &&
	    xs_verdict_drops(verdict)) {
		action = XDP_DROP;
		goto out;
	}

deliver:
	fail = xs_deliver(ctx, &pkt, &asset);
	if (fail) {
		verdict = fail;
		action = XDP_DROP;
	} else {
		action = XDP_TX;
	}
out:
	/* Bytes counted as received, before any rewrite. */
	xs_count(tenant, verdict, pkt_len);
	return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
