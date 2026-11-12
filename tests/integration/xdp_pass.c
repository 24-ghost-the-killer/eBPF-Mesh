// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Minimal pass-through program for the client side of the veth pair.
 * veth delivers XDP_TX frames to its peer only if the peer runs NAPI, which
 * attaching any XDP program enables. Real NICs do not need this.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xs_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
