/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * maps.h - BPF map definitions (BTF-defined maps).
 *
 * Maps are added phase by phase, so every map in the object is exercised by
 * tests. Pinning is decided by the loader (meshctl sets a per-interface pin
 * path on every map before load), not by a `pinning` attribute here, so
 * tests can load the object without touching /sys/fs/bpf and two interfaces
 * never silently share maps.
 */
#ifndef EM_MAPS_H
#define EM_MAPS_H

#include "compat.h"
#include "abi.h"

/*
 * Global counters. PERCPU_ARRAY with a single element holding every counter:
 *   - per-CPU: no atomics, no cache-line bouncing between RX cores;
 *   - one element: exactly one map lookup per packet regardless of how many
 *     counters are touched;
 *   - userspace reads all CPUs' copies with a single lookup syscall and sums.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct em_stats);
} em_stats SEC(".maps");

#endif /* EM_MAPS_H */
