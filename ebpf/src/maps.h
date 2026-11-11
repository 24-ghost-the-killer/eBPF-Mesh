/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* BPF map definitions. Userspace pins these under $SENTINEL_PIN_DIR. */
#ifndef XS_MAPS_H
#define XS_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "abi.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xs_cfg);
} xs_cfg SEC(".maps");

/* Phase 2: the single default policy. Replaced by per-asset values in phase 3. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xs_policy);
} xs_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XS_RULES_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xs_src_key);
	__type(value, struct xs_rule);
} xs_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XS_RULES_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xs_src6_key);
	__type(value, struct xs_rule);
} xs_allow6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XS_RULES_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xs_src_key);
	__type(value, struct xs_rule);
} xs_block SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XS_RULES_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xs_src6_key);
	__type(value, struct xs_rule);
} xs_block6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XS_SERVICES_MAX_ENTRIES);
	__type(key, struct xs_svc_key);
	__type(value, __u8);
} xs_services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XS_RL_MAX_ENTRIES);
	__type(key, struct xs_addr_key);
	__type(value, struct xs_rl);
} xs_rl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XS_VERIFIED_MAX_ENTRIES);
	__type(key, struct xs_addr_key);
	__type(value, __u64);
} xs_verified SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, XS_STATS_MAX_ENTRIES);
	__type(key, struct xs_stats_key);
	__type(value, struct xs_stats_val);
} xs_stats SEC(".maps");

#endif /* XS_MAPS_H */
