// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * em_xdp.c - eBPF Mesh XDP dataplane entry point.
 *
 * Phase 0 pipeline (per frame), observe-only:
 *
 *   1. one PERCPU_ARRAY lookup -> per-CPU counter block
 *   2. bounded L2-L4 parse     -> struct em_pkt on the stack
 *   3. counter updates         -> plain stores into the per-CPU block
 *   4. verdict                 -> always XDP_PASS
 *
 * No helper other than the map lookup is called; nothing blocks, nothing
 * allocates, nothing waits for userspace. Later phases insert filtering
 * (Phase 1), tenant lookup (Phase 2) and encapsulation (Phase 3) between
 * steps 3 and 4 (docs/architecture.md).
 */
#include "compat.h"
#include "abi.h"
#include "parsers.h"
#include "account.h"
#include "maps.h"

/*
 * Verification boundary. em_parse() is a *global* (non-static, noinline)
 * BPF-to-BPF function, so the verifier checks it exactly once, independently
 * of its call site, and the caller sees the returned rc and *p as unknown
 * values. Without the boundary every distinct parser outcome (VLAN depth x L3
 * x IPv6 extension chain x fragment state x L4 result) is carried as a
 * separate verifier state through all later stages, and the verified
 * instruction count grows by orders of magnitude. Runtime cost is one BPF
 * call (a few ns); the JIT emits a direct call.
 */
__attribute__((noinline)) int em_parse(struct xdp_md *ctx, struct em_pkt *p)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (!p) /* global functions must handle a NULL pointer argument */
		return EM_PARSE_ERR_ETH_TRUNC;
	return em_parse_packet(data, data_end, p);
}

SEC("xdp")
int em_xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	const __u32 zero = 0;
	struct em_pkt pkt = {};
	struct em_stats *st;
	__u64 len = data_end - data;
	int rc;

	st = bpf_map_lookup_elem(&em_stats, &zero);
	if (!st)
		return XDP_PASS; /* cannot happen for index 0; required by the verifier */

	em_count(st, EM_CNT_RX, len);

	/*
	 * The verifier treats a global function's return value as an unknown
	 * scalar, but clang may propagate em_parse()'s real return range across
	 * the call and delete the range check in em_account_parse() that the
	 * verifier needs for the rc-indexed slot. Hiding rc from the optimiser
	 * keeps that check in the object.
	 */
	rc = em_opaque(em_parse(ctx, &pkt));
	em_account_parse(st, &pkt, rc, len);

	em_count(st, EM_CNT_VERDICT_PASS, len);
	return XDP_PASS;
}

/* GPL-compatible: later phases use GPL-only helpers (e.g. SYN cookies). */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
