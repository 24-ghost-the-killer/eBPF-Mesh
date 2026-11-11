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
 *  - Times are CLOCK_BOOTTIME nanoseconds (bpf_ktime_get_boot_ns()).
 */
#ifndef XS_ABI_H
#define XS_ABI_H

#include <linux/types.h>

#define XS_ABI_VERSION 3

/* Parser limits (compile-time bounds for the verifier). */
#define XS_MAX_VLAN_TAGS 2
#define XS_MAX_IPV6_EXT_HDRS 4

/* Map sizes. */
#define XS_STATS_MAX_ENTRIES 65536
#define XS_RULES_MAX_ENTRIES 65536
#define XS_SERVICES_MAX_ENTRIES 4096
#define XS_RL_MAX_ENTRIES 262144
#define XS_VERIFIED_MAX_ENTRIES 262144
#define XS_TENANTS_MAX_ENTRIES 65536

/* Tenant 0 means "global" / "no tenant". */
#define XS_TENANT_GLOBAL 0

/* Rate limiting groups IPv6 sources by this prefix length. */
#define XS_RL_V6_PREFIX 64

/* Outer IPv4 header added by the tunnel, and the MTU assumed if unset. */
#define XS_TUNNEL_OVERHEAD 20
#define XS_DEFAULT_MTU 1500

/* Default lifetime of a verified (SYN-cookie authenticated) source. */
#define XS_VERIFY_TTL_DEFAULT_S 300

/* xs_cfg.flags: global switches. */
#define XS_CFG_F_OBSERVE (1U << 0) /* kill switch: count verdicts, never drop */

/* xs_policy.flags */
#define XS_P_MITIGATE (1U << 0)   /* drop/challenge; unset = observe (default) */
#define XS_P_SYNCOOKIE (1U << 1)  /* authenticate TCP sources with SYN cookies */
#define XS_P_SERVICES (1U << 2)   /* enforce the allowed-services list */
#define XS_P_ALLOW_FRAG (1U << 3) /* pass non-first fragments */

/*
 * Verdicts. Counted per (tenant, verdict) in xs_stats. In observe mode the
 * verdict a packet would get is counted, but the packet is passed.
 * Append-only.
 */
enum xs_verdict {
	XS_V_PASS = 0,              /* passed every check */
	XS_V_DROP_MALFORMED = 1,    /* failed validation */
	XS_V_PASS_NON_IP = 2,       /* ARP, LLDP, ...: left to the kernel */
	XS_V_FRAGMENT = 3,          /* non-first fragment, passed (policy allows) */
	XS_V_PASS_LOCAL = 4,        /* to the PoP itself (unicast IP, IPv6 ND) */
	XS_V_DROP_BOGON = 5,        /* bogon source address */
	XS_V_PASS_ALLOW = 6,        /* allowlisted source */
	XS_V_DROP_BLOCK = 7,        /* blocklisted source */
	XS_V_DROP_SERVICE = 8,      /* protocol/port not in allowed services */
	XS_V_DROP_FRAGMENT = 9,     /* non-first fragment, policy drops them */
	XS_V_DROP_RATELIMIT = 10,   /* per-source token bucket empty */
	XS_V_TX_SYN_CHALLENGE = 11, /* SYN answered with a cookie SYN-ACK */
	XS_V_SYN_VERIFIED = 12,     /* RST carried a valid cookie: source verified */
	XS_V_DROP_UNVERIFIED = 13,  /* TCP from a source that is not verified */
	XS_V_DROP_NO_TENANT = 14,   /* destination is not a protected prefix */
	XS_V_DROP_TOO_BIG = 15,     /* does not fit the uplink MTU once tunnelled */
	XS_V_DROP_TUNNEL = 16,      /* cannot tunnel: PoP IP / origin missing */
	XS_V_TX_RETURN = 17,        /* origin's reply decapsulated and forwarded */
	XS_V_DROP_RETURN = 18,      /* invalid return traffic (unknown origin, spoofing) */
	XS_V__COUNT = 19,           /* number of verdicts; not a verdict */
};

/* Why a rule exists (xs_rule.reason). Append-only. */
enum xs_reason {
	XS_R_NONE = 0,
	XS_R_MANUAL = 1, /* added by an operator */
};

/* xs_cfg: ARRAY, one entry at key 0. Written by userspace. */
struct xs_cfg {
	__u32 flags;
	__be32 pop_ip4;       /* PoP unicast IPv4; 0 = unset */
	__u8 pop_ip6[16];     /* PoP unicast IPv6; all-zero = unset */
	__u64 cookie_key[2];  /* SipHash key for SYN cookies; zero = disabled */
	__u32 verify_ttl_s;   /* lifetime of a verified source; 0 = default */
	__be32 tunnel_ep4;    /* anycast endpoint for origin replies; 0 = none */
	__u8 nexthop_mac[6];  /* uplink router; all-zero = back to the sender */
	__u16 uplink_mtu;     /* 0 = XS_DEFAULT_MTU */
};

/* Per-asset policy, embedded in struct xs_asset. */
struct xs_policy {
	__u32 flags;       /* XS_P_* */
	__u32 pps_per_src; /* token bucket rate; 0 = no rate limit */
	__u32 burst;       /* bucket size in packets; 0 = pps_per_src */
	__u32 _pad;
};

/*
 * xs_tenants / xs_tenants6: LPM, protected prefix -> asset (ADR 0004: one
 * entry per protected prefix, carrying the owning tenant and its policy).
 */
struct xs_tenant_key {
	__u32 prefixlen;
	__be32 addr;
};

struct xs_tenant6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct xs_asset {
	__u32 tenant;
	__u32 asset;            /* asset id; key of xs_services */
	__be32 origin4;         /* tunnel destination (customer server) */
	__u32 _pad;
	struct xs_policy policy;
};

/* xs_allow / xs_block (LPM). prefixlen = 32 (tenant) + source prefix length. */
struct xs_src_key {
	__u32 prefixlen;
	__u32 tenant;
	__be32 src;
};

struct xs_src6_key {
	__u32 prefixlen;
	__u32 tenant;
	__u8 src[16];
};

struct xs_rule {
	__u64 expires_ns; /* allow: 0 = permanent; block: must be > 0 */
	__u32 reason;     /* enum xs_reason */
	__u32 _pad;
};

/* xs_services: HASH {asset, proto, port} -> 1. port 0 = whole protocol. */
struct xs_svc_key {
	__u32 asset;
	__u8 proto;
	__u8 _pad;
	__be16 port;
};

/*
 * xs_rl / xs_verified key: IPv4 as ::ffff:a.b.c.d. For xs_rl, IPv6 sources
 * are masked to XS_RL_V6_PREFIX bits.
 */
struct xs_addr_key {
	__u32 tenant;
	__u8 addr[16];
};

/* xs_rl: LRU_HASH xs_addr_key -> bucket. tokens are in units of 1e-9 packet. */
struct xs_rl {
	__u64 tokens;
	__u64 last_ns;
};

/* xs_verified: LRU_HASH xs_addr_key -> __u64 expires_ns. */

/* xs_stats: PERCPU_HASH {tenant, verdict} -> {pkts, bytes}. */
struct xs_stats_key {
	__u32 tenant;
	__u32 verdict;
};

struct xs_stats_val {
	__u64 pkts;
	__u64 bytes;
};

_Static_assert(sizeof(struct xs_cfg) == 56, "xs_cfg size");
_Static_assert(_Alignof(struct xs_cfg) == 8, "xs_cfg align");
_Static_assert(sizeof(struct xs_policy) == 16, "xs_policy size");
_Static_assert(_Alignof(struct xs_policy) == 4, "xs_policy align");
_Static_assert(sizeof(struct xs_tenant_key) == 8, "xs_tenant_key size");
_Static_assert(_Alignof(struct xs_tenant_key) == 4, "xs_tenant_key align");
_Static_assert(sizeof(struct xs_tenant6_key) == 20, "xs_tenant6_key size");
_Static_assert(_Alignof(struct xs_tenant6_key) == 4, "xs_tenant6_key align");
_Static_assert(sizeof(struct xs_asset) == 32, "xs_asset size");
_Static_assert(_Alignof(struct xs_asset) == 4, "xs_asset align");
_Static_assert(sizeof(struct xs_src_key) == 12, "xs_src_key size");
_Static_assert(_Alignof(struct xs_src_key) == 4, "xs_src_key align");
_Static_assert(sizeof(struct xs_src6_key) == 24, "xs_src6_key size");
_Static_assert(_Alignof(struct xs_src6_key) == 4, "xs_src6_key align");
_Static_assert(sizeof(struct xs_rule) == 16, "xs_rule size");
_Static_assert(_Alignof(struct xs_rule) == 8, "xs_rule align");
_Static_assert(sizeof(struct xs_svc_key) == 8, "xs_svc_key size");
_Static_assert(_Alignof(struct xs_svc_key) == 4, "xs_svc_key align");
_Static_assert(sizeof(struct xs_addr_key) == 20, "xs_addr_key size");
_Static_assert(_Alignof(struct xs_addr_key) == 4, "xs_addr_key align");
_Static_assert(sizeof(struct xs_rl) == 16, "xs_rl size");
_Static_assert(_Alignof(struct xs_rl) == 8, "xs_rl align");
_Static_assert(sizeof(struct xs_stats_key) == 8, "xs_stats_key size");
_Static_assert(_Alignof(struct xs_stats_key) == 4, "xs_stats_key align");
_Static_assert(sizeof(struct xs_stats_val) == 16, "xs_stats_val size");
_Static_assert(_Alignof(struct xs_stats_val) == 8, "xs_stats_val align");

#endif /* XS_ABI_H */
