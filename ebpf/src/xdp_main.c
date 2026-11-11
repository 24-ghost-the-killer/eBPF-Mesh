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
 *   9. sample 1 in N parsed packets (any verdict) to xs_events
 *  10. deliver: encapsulate to the asset's origin, XDP_TX
 *
 * [global] drops obey only the XS_CFG_F_OBSERVE kill switch. [policy] drops
 * and challenges happen only when the asset's policy has XS_P_MITIGATE (and
 * the kill switch is off). In observe mode the verdict is counted and the
 * packet is still delivered through the tunnel.
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

/*
 * Step 9: sample 1 in cfg->sample_rate packets into the ring buffer for the
 * agent's flow telemetry. Global function, verified once.
 */
__attribute__((noinline)) int xs_sample(struct xs_pkt *pkt, __u32 tenant,
					__u32 asset, __u32 verdict, __u32 len)
{
	__u32 zero = 0, rate;
	const struct xs_cfg *cfg = bpf_map_lookup_elem(&xs_cfg, &zero);
	struct xs_event *e;

	if (!pkt || !cfg || !cfg->sample_rate)
		return 0;
	rate = cfg->sample_rate;
	if (rate > 1 && bpf_get_prandom_u32() % rate)
		return 0;
	e = bpf_ringbuf_reserve(&xs_events, sizeof(*e), 0);
	if (!e) {
		__u64 *lost = bpf_map_lookup_elem(&xs_counters, &zero); /* XS_C_EVENTS_LOST */

		if (lost)
			(*lost)++;
		return 0;
	}
	e->ts = bpf_ktime_get_boot_ns();
	e->tenant = tenant;
	e->asset = asset;
	if (pkt->l3_proto == ETH_P_IP) {
		__builtin_memset(e->src, 0, 10);
		e->src[10] = e->src[11] = 0xff;
		__builtin_memcpy(&e->src[12], &pkt->src4, 4);
		__builtin_memset(e->dst, 0, 10);
		e->dst[10] = e->dst[11] = 0xff;
		__builtin_memcpy(&e->dst[12], &pkt->dst4, 4);
		e->family = 4;
	} else {
		__builtin_memcpy(e->src, &pkt->src6, 16);
		__builtin_memcpy(e->dst, &pkt->dst6, 16);
		e->family = 6;
	}
	e->sport = pkt->sport;
	e->dport = pkt->dport;
	e->proto = pkt->l4_proto;
	e->tcp_flags = pkt->tcp_flags;
	e->verdict = verdict;
	e->len = len > 0xffff ? 0xffff : len;
	e->_pad = 0;
	e->sample_rate = rate;
	bpf_ringbuf_submit(e, 0);
	return 1;
}

SEC("xdp")
int xs_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 pkt_len = data_end - data;
	__u32 zero = 0, verdict, fail, tenant = XS_TENANT_GLOBAL, asset_id = 0;
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
		/* Origins' replies: not sampled (telemetry is about inbound). */
		verdict = xs_return(ctx, &pkt, &tenant);
		if (verdict == XS_V_TX_RETURN)
			action = XDP_TX;
		else
			action = global_observe ? XDP_PASS : XDP_DROP;
		xs_count(tenant, verdict, pkt_len);
		return action;
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
		asset_id = asset.asset;
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
	if (rc == XS_P_OK || rc == XS_P_FRAGMENT)
		xs_sample(&pkt, tenant, asset_id, verdict, pkt_len);
	return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
