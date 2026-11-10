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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, XS_STATS_MAX_ENTRIES);
	__type(key, struct xs_stats_key);
	__type(value, struct xs_stats_val);
} xs_stats SEC(".maps");

#endif /* XS_MAPS_H */
