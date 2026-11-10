/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Sentinel-Edge kernel/userspace ABI.
 *
 * This is the single source of truth for every struct and constant shared
 * between the XDP program and userspace. crates/common/src/abi.rs mirrors it
 * exactly; both sides assert sizes and alignment, and a Rust test parses this
 * file to check that the constants agree.
 *
 * Rules:
 *  - Only fixed-width types, explicit padding, no implicit holes.
 *  - Enums are append-only: never renumber an existing value.
 */
#ifndef XS_ABI_H
#define XS_ABI_H

#include <linux/types.h>

#define XS_ABI_VERSION 1

/* Parser limits (compile-time bounds for the verifier). */
#define XS_MAX_VLAN_TAGS 2
#define XS_MAX_IPV6_EXT_HDRS 4

/* Map sizes. */
#define XS_STATS_MAX_ENTRIES 65536

/* Tenant 0 means "global" / "no tenant". */
#define XS_TENANT_GLOBAL 0

/* xs_cfg.flags */
#define XS_CFG_F_OBSERVE (1U << 0) /* count verdicts, never drop */

/*
 * Verdicts. Counted per (tenant, verdict) in xs_stats.
 * Append-only: later phases add values after XS_V_FRAGMENT.
 */
enum xs_verdict {
	XS_V_PASS = 0,           /* well-formed, allowed */
	XS_V_DROP_MALFORMED = 1, /* failed validation */
	XS_V_PASS_NON_IP = 2,    /* ARP, LLDP, ...: left to the kernel */
	XS_V_FRAGMENT = 3,       /* non-first IP fragment (no L4 header) */
	XS_V__COUNT = 4,         /* number of verdicts; not a verdict */
};

/* xs_cfg: ARRAY, one entry at key 0. Written by userspace. */
struct xs_cfg {
	__u32 flags;
	__u32 _pad;
};

/* xs_stats: PERCPU_HASH {tenant, verdict} -> {pkts, bytes}. */
struct xs_stats_key {
	__u32 tenant;
	__u32 verdict;
};

struct xs_stats_val {
	__u64 pkts;
	__u64 bytes;
};

_Static_assert(sizeof(struct xs_cfg) == 8, "xs_cfg size");
_Static_assert(_Alignof(struct xs_cfg) == 4, "xs_cfg align");
_Static_assert(sizeof(struct xs_stats_key) == 8, "xs_stats_key size");
_Static_assert(_Alignof(struct xs_stats_key) == 4, "xs_stats_key align");
_Static_assert(sizeof(struct xs_stats_val) == 16, "xs_stats_val size");
_Static_assert(_Alignof(struct xs_stats_val) == 8, "xs_stats_val align");

#endif /* XS_ABI_H */
