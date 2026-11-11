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
	int prog, cfg, stats, tenants, tenants6;
	int allow, allow6, block, block6, services, rl, verified;
};

/*
 * Default test setup (reset_state): assets for DST4/32 (id 1) and DST6/128
 * (id 2), both owned by TEST_TENANT, tunnelled to TEST_ORIGIN; the PoP's
 * unicast address is TEST_POP_IP.
 */
#define TEST_TENANT 7
#define TEST_ASSET4 1
#define TEST_ASSET6 2
static const uint8_t TEST_POP_IP[4] = { 10, 10, 1, 1 };
static const uint8_t TEST_ORIGIN[4] = { 192, 0, 2, 10 };
static const uint8_t TEST_TUNNEL_EP[4] = { 198, 51, 100, 1 };

extern struct xs_fds fd;

/* CLOCK_BOOTTIME ns, the clock bpf_ktime_get_boot_ns() uses. */
uint64_t boot_ns(void);

/* Empties every map, installs the default assets (observe mode) and a cfg
 * with only TEST_POP_IP set. */
void reset_state(void);
void map_clear(int map_fd);
/* Writes cfg; a zero pop_ip4 is replaced by TEST_POP_IP. */
void set_cfg(const struct xs_cfg *c);
/* Writes cfg exactly as given. */
void set_cfg_raw(const struct xs_cfg *c);
/* Policy of both default assets. */
void set_policy(uint32_t flags, uint32_t pps, uint32_t burst);
void add_asset4(const uint8_t addr[4], int len, uint32_t tenant, uint32_t id,
		const uint8_t origin[4], uint32_t flags);
void add_asset6(const uint8_t addr[16], int len, uint32_t tenant, uint32_t id,
		const uint8_t origin[4], uint32_t flags);
/* Packets counted for (tenant, verdict), summed over CPUs. */
uint64_t stat_pkts(uint32_t tenant, int verdict);

void add_rule4(int map_fd, uint32_t tenant, const uint8_t addr[4], int len,
	       uint64_t expires_ns);
void add_rule6(int map_fd, uint32_t tenant, const uint8_t addr[16], int len,
	       uint64_t expires_ns);
/* Allowed service on both default assets. */
void add_service(uint8_t proto, uint16_t port);
void add_service_for(uint32_t asset, uint8_t proto, uint16_t port);

/* Checksums (tests compute them independently of the program). */
uint16_t csum_fold16(uint32_t sum);
uint32_t csum_sum(const uint8_t *b, size_t n);
/* Recomputes the TCP checksum of the IPv4 / IPv6 packet at ip_off. */
void fix_tcp_csum4(struct pkt *p, size_t ip_off);
void fix_tcp_csum6(struct pkt *p, size_t ip6_off);
/* 1 if the TCP checksum of the packet at ip_off is valid. */
int tcp_csum_ok4(const uint8_t *ip);
int tcp_csum_ok6(const uint8_t *ip6);

/*
 * The frame XDP should produce when tunnelling `in` (L3 at offset l3) from
 * TEST_POP_IP to origin, sent to dst_mac (NULL: back to in's source MAC).
 */
void expected_encap(struct pkt *e, const struct pkt *in, size_t l3,
		    const uint8_t origin[4], const uint8_t *dst_mac);
/* Records a check that out equals expected byte for byte. */
int check_bytes(const char *name, const struct pkt *out, const struct pkt *want);

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
void run_tunnel_tests(void);

#endif /* XS_HARNESS_H */
