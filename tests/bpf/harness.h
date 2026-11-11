/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Shared infrastructure of the BPF_PROG_TEST_RUN tests. */
#ifndef XS_HARNESS_H
#define XS_HARNESS_H

#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>

#include "../common/pktbuild.h"
#include "../../ebpf/include/abi.h"

struct xs_fds {
	int prog, cfg, policy, stats;
	int allow, allow6, block, block6, services, rl, verified;
};

extern struct xs_fds fd;

/* CLOCK_BOOTTIME ns, the clock bpf_ktime_get_boot_ns() uses. */
uint64_t boot_ns(void);

/* Empties every rule/service/rate-limit/verified map; zero cfg and policy. */
void reset_state(void);
void map_clear(int map_fd);
void set_cfg(const struct xs_cfg *c);
void set_policy(uint32_t flags, uint32_t pps, uint32_t burst);

void add_rule4(int map_fd, uint32_t tenant, const uint8_t addr[4], int len,
	       uint64_t expires_ns);
void add_rule6(int map_fd, uint32_t tenant, const uint8_t addr[16], int len,
	       uint64_t expires_ns);
void add_service(uint8_t proto, uint16_t port);

/*
 * Runs frame p through the program. Checks the XDP action and that exactly
 * one packet of p->len bytes was counted, under (tenant 0, verdict) only.
 * If out is non-NULL it receives the output frame. Returns 1 on success.
 */
int expect(const char *name, const struct pkt *p, int action, int verdict,
	   struct pkt *out);

/* Records a named check. Returns ok. */
int check(const char *name, int ok, const char *why);

void run_policy_tests(void);

#endif /* XS_HARNESS_H */
