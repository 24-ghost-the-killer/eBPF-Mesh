/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * abi.h - the ABI between the XDP dataplane and userspace.
 *
 * This file is the single source of truth. userspace/common/src/abi.rs
 * mirrors it, and a Rust test parses this file to detect drift. Rules:
 *
 *   * enumerators carry explicit values; a value is never reused for a
 *     different meaning once released (dashboards and history depend on it);
 *   * struct sizes are fixed and asserted here and in abi.rs; pinned maps
 *     are reused across upgrades and the kernel refuses to reuse a pinned map
 *     whose key/value size changed, so sizes reserve room for growth;
 *   * counters are monotonic. The dataplane never resets them; userspace
 *     computes deltas with wrapping subtraction.
 */
#ifndef EM_ABI_H
#define EM_ABI_H

#include "compat.h"

#define EM_ABI_VERSION 1

/*
 * Counter slots in the per-CPU stats map (em_stats). Each slot holds a packet
 * and a byte counter. Gaps are reserved for later phases.
 */
enum em_counter_id {
	/* Every frame seen by the program. */
	EM_CNT_RX                    = 0,

	/* Final verdicts. PASS + DROP + TX + REDIRECT == RX. Phase 0 only PASSes. */
	EM_CNT_VERDICT_PASS          = 1,
	EM_CNT_VERDICT_DROP          = 2,
	EM_CNT_VERDICT_TX            = 3,
	EM_CNT_VERDICT_REDIRECT      = 4,

	/* L2: VLAN tag depth. */
	EM_CNT_L2_VLAN1              = 8,  /* exactly one 802.1Q/802.1ad tag */
	EM_CNT_L2_VLAN2              = 9,  /* two tags (QinQ) */

	/* L3: counted whenever the L3 header itself was valid. */
	EM_CNT_L3_IPV4               = 16,
	EM_CNT_L3_IPV6               = 17,
	EM_CNT_L3_ARP                = 18,
	EM_CNT_L3_OTHER              = 19, /* any other ethertype / 802.3 length */

	/* L4: counted for fully parsed IP packets (parse rc == OK), including
	 * non-first fragments (protocol known from the IP header). */
	EM_CNT_L4_TCP                = 24,
	EM_CNT_L4_UDP                = 25,
	EM_CNT_L4_ICMP               = 26,
	EM_CNT_L4_ICMPV6             = 27,
	EM_CNT_L4_OTHER              = 28,

	/* Fragmentation / IPv6 extension headers (rc == OK only). */
	EM_CNT_FRAG_FIRST            = 32,
	EM_CNT_FRAG_LATER            = 33,
	EM_CNT_IPV6_EXT              = 34, /* >= 1 extension header traversed */

	/* TCP flag classes (only when the TCP header was parsed). */
	EM_CNT_TCP_SYN               = 40, /* SYN && !ACK */
	EM_CNT_TCP_SYNACK            = 41, /* SYN && ACK */
	EM_CNT_TCP_ACK               = 42, /* ACK && !SYN && !FIN && !RST */
	EM_CNT_TCP_FIN               = 43, /* FIN set */
	EM_CNT_TCP_RST               = 44, /* RST set */

	/* Header anomalies on fully parsed packets (rc == OK). Counted only;
	 * Phase 0 never drops. */
	EM_CNT_ANOM_IPV4_OPTIONS     = 48,
	EM_CNT_ANOM_TCP_BAD_FLAGS    = 49,
	EM_CNT_ANOM_UDP_LEN_MISMATCH = 50,
	EM_CNT_ANOM_LAND             = 51,
	EM_CNT_ANOM_TTL_ZERO         = 52,
	EM_CNT_ANOM_PORT_ZERO        = 53,

	/* Parse outcome histogram: slot EM_CNT_PARSE_BASE + enum em_parse_rc.
	 * Exactly one outcome per frame, so the sum over these slots == RX. */
	EM_CNT_PARSE_BASE            = 64,

	EM_CNT_SLOTS                 = 128,
};

/*
 * Parser result. Three classes:
 *   OK / NOT_IP   - well formed.
 *   UNSUP_*       - legal but beyond what the fast path parses (always
 *                   passed, never treated as malformed; RFC 7045 spirit).
 *   ERR_*         - malformed per the relevant RFC.
 */
enum em_parse_rc {
	EM_PARSE_OK                   = 0,
	EM_PARSE_NOT_IP               = 1,
	EM_PARSE_UNSUP_VLAN_DEPTH     = 2,
	EM_PARSE_UNSUP_IPV6_EXT_DEPTH = 3,

	EM_PARSE_ERR_FIRST            = 8,
	EM_PARSE_ERR_ETH_TRUNC        = 8,
	EM_PARSE_ERR_VLAN_TRUNC       = 9,
	EM_PARSE_ERR_IPV4_TRUNC       = 10,
	EM_PARSE_ERR_IPV4_VERSION     = 11,
	EM_PARSE_ERR_IPV4_IHL         = 12,
	EM_PARSE_ERR_IPV4_TOTLEN      = 13,
	EM_PARSE_ERR_IPV6_TRUNC       = 14,
	EM_PARSE_ERR_IPV6_VERSION     = 15,
	EM_PARSE_ERR_IPV6_PLEN        = 16,
	EM_PARSE_ERR_IPV6_EXT_TRUNC   = 17,
	EM_PARSE_ERR_FRAG_TINY        = 18,
	EM_PARSE_ERR_TCP_TRUNC        = 19,
	EM_PARSE_ERR_TCP_DOFF         = 20,
	EM_PARSE_ERR_UDP_TRUNC        = 21,
	EM_PARSE_ERR_UDP_LEN          = 22,
	EM_PARSE_ERR_ICMP_TRUNC       = 23,

	EM_PARSE_RC_MAX               = 24,
};

struct em_counter {
	__u64 packets;
	__u64 bytes;
};

/* Value of the single-entry PERCPU_ARRAY em_stats: 2 KiB per CPU. */
struct em_stats {
	struct em_counter c[EM_CNT_SLOTS];
};

_Static_assert(sizeof(struct em_counter) == 16, "em_counter ABI");
_Static_assert(sizeof(struct em_stats) == 2048, "em_stats ABI");
_Static_assert(EM_CNT_PARSE_BASE + EM_PARSE_RC_MAX <= EM_CNT_SLOTS, "counter slots");

#endif /* EM_ABI_H */
