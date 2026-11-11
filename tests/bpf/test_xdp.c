// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * BPF_PROG_TEST_RUN tests for the XDP program.
 *
 * Every case runs a crafted frame through the real, verified program and
 * checks (1) the XDP action, (2) that exactly one packet with the frame's
 * length was counted under the expected (tenant 0, verdict) key and nowhere
 * else, and for rewritten frames (3) the exact output bytes.
 *
 * Suites: parser (cases.h), policy and SYN cookies (policy_tests.c).
 *
 * Usage: test_xdp <path/to/xdp_main.o>      (needs root / CAP_BPF)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "harness.h"
#include "cases.h"

struct xs_fds fd;
static int ncpu, failures, runs;

static const char *verdict_names[XS_V__COUNT] = {
	"pass", "drop_malformed", "pass_non_ip", "fragment", "pass_local",
	"drop_bogon", "pass_allow", "drop_block", "drop_service",
	"drop_fragment", "drop_ratelimit", "tx_syn_challenge", "syn_verified",
	"drop_unverified", "drop_no_tenant", "drop_too_big", "drop_tunnel",
	"tx_return", "drop_return",
};

static const char *verdict_name(int v)
{
	return v >= 0 && v < XS_V__COUNT ? verdict_names[v] : "?";
}

static const char *action_name(int a)
{
	return a == XDP_PASS ? "XDP_PASS" : a == XDP_DROP ? "XDP_DROP" :
	       a == XDP_TX ? "XDP_TX" : "other";
}

uint64_t boot_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void die(const char *what)
{
	perror(what);
	exit(2);
}

void map_clear(int map_fd)
{
	uint8_t key[64], next[64];

	/* Deleting while iterating restarts from the first key. */
	while (bpf_map_get_next_key(map_fd, NULL, next) == 0) {
		memcpy(key, next, sizeof(key));
		if (bpf_map_delete_elem(map_fd, key))
			die("map_clear");
	}
}

void set_cfg_raw(const struct xs_cfg *c)
{
	__u32 zero = 0;

	if (bpf_map_update_elem(fd.cfg, &zero, c, BPF_ANY))
		die("update xs_cfg");
}

void set_cfg(const struct xs_cfg *c)
{
	struct xs_cfg copy = *c;

	if (!copy.pop_ip4)
		memcpy(&copy.pop_ip4, TEST_POP_IP, 4);
	set_cfg_raw(&copy);
}

static void put_asset4(const uint8_t addr[4], int len, const struct xs_asset *a)
{
	struct xs_tenant_key k = { .prefixlen = len };

	memcpy(&k.addr, addr, 4);
	if (bpf_map_update_elem(fd.tenants, &k, a, BPF_ANY))
		die("update xs_tenants");
}

static void put_asset6(const uint8_t addr[16], int len, const struct xs_asset *a)
{
	struct xs_tenant6_key k = { .prefixlen = len };

	memcpy(k.addr, addr, 16);
	if (bpf_map_update_elem(fd.tenants6, &k, a, BPF_ANY))
		die("update xs_tenants6");
}

void add_asset4(const uint8_t addr[4], int len, uint32_t tenant, uint32_t id,
		const uint8_t origin[4], uint32_t flags)
{
	struct xs_asset a = { .tenant = tenant, .asset = id,
			      .policy = { .flags = flags } };

	memcpy(&a.origin4, origin, 4);
	put_asset4(addr, len, &a);
}

void add_asset6(const uint8_t addr[16], int len, uint32_t tenant, uint32_t id,
		const uint8_t origin[4], uint32_t flags)
{
	struct xs_asset a = { .tenant = tenant, .asset = id,
			      .policy = { .flags = flags } };

	memcpy(&a.origin4, origin, 4);
	put_asset6(addr, len, &a);
}

void set_policy(uint32_t flags, uint32_t pps, uint32_t burst)
{
	struct xs_asset a = { .tenant = TEST_TENANT,
			      .policy = { .flags = flags, .pps_per_src = pps,
					  .burst = burst } };

	memcpy(&a.origin4, TEST_ORIGIN, 4);
	a.asset = TEST_ASSET4;
	put_asset4(DST4, 32, &a);
	a.asset = TEST_ASSET6;
	put_asset6(DST6, 128, &a);
}

void reset_state(void)
{
	struct xs_cfg c = { 0 };

	map_clear(fd.tenants);
	map_clear(fd.tenants6);
	map_clear(fd.allow);
	map_clear(fd.allow6);
	map_clear(fd.block);
	map_clear(fd.block6);
	map_clear(fd.services);
	map_clear(fd.rl);
	map_clear(fd.verified);
	set_cfg(&c);
	set_policy(0, 0, 0);
}

uint16_t csum_fold16(uint32_t s)
{
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (uint16_t)~s;
}

uint32_t csum_sum(const uint8_t *b, size_t n)
{
	uint32_t s = 0;

	for (size_t i = 0; i + 1 < n; i += 2)
		s += (uint32_t)b[i] << 8 | b[i + 1];
	if (n & 1)
		s += (uint32_t)b[n - 1] << 8;
	return s;
}

static uint32_t tcp_pseudo4(const uint8_t *ip, size_t tcplen)
{
	return csum_sum(ip + 12, 8) + 6 + tcplen;
}

static uint32_t tcp_pseudo6(const uint8_t *ip6, size_t tcplen)
{
	return csum_sum(ip6 + 8, 32) + 6 + tcplen;
}

void fix_tcp_csum4(struct pkt *p, size_t ip_off)
{
	uint8_t *ip = p->b + ip_off;
	size_t ihl = (ip[0] & 0xf) * 4, tot = (size_t)ip[2] << 8 | ip[3];
	uint8_t *t = ip + ihl;

	w16(t + 16, 0);
	w16(t + 16, csum_fold16(tcp_pseudo4(ip, tot - ihl) + csum_sum(t, tot - ihl)));
}

void fix_tcp_csum6(struct pkt *p, size_t ip6_off)
{
	uint8_t *ip = p->b + ip6_off;
	size_t plen = (size_t)ip[4] << 8 | ip[5];
	uint8_t *t = ip + 40;

	w16(t + 16, 0);
	w16(t + 16, csum_fold16(tcp_pseudo6(ip, plen) + csum_sum(t, plen)));
}

int tcp_csum_ok4(const uint8_t *ip)
{
	size_t ihl = (ip[0] & 0xf) * 4, tot = (size_t)ip[2] << 8 | ip[3];

	return csum_fold16(tcp_pseudo4(ip, tot - ihl) + csum_sum(ip + ihl, tot - ihl)) == 0;
}

int tcp_csum_ok6(const uint8_t *ip)
{
	size_t plen = (size_t)ip[4] << 8 | ip[5];

	return csum_fold16(tcp_pseudo6(ip, plen) + csum_sum(ip + 40, plen)) == 0;
}

void expected_encap(struct pkt *e, const struct pkt *in, size_t l3,
		    const uint8_t origin[4], const uint8_t *dst_mac)
{
	const uint8_t *inner = in->b + l3;
	int v6 = (inner[0] >> 4) == 6;
	size_t ip_len = v6 ? 40 + ((size_t)inner[4] << 8 | inner[5]) :
			     ((size_t)inner[2] << 8 | inner[3]);
	uint8_t *o;

	memset(e, 0, sizeof(*e));
	put(e, in->b, l3);
	memcpy(e->b + 6, in->b, 6); /* source = our NIC (old destination) */
	memcpy(e->b, dst_mac ? dst_mac : in->b + 6, 6);
	w16(e->b + l3 - 2, 0x0800);
	o = put(e, NULL, 20);
	o[0] = 0x45;
	o[1] = v6 ? (uint8_t)((inner[0] << 4) | (inner[1] >> 4)) : inner[1];
	w16(o + 2, ip_len + 20);
	w16(o + 6, 0x4000);
	o[8] = 64;
	o[9] = v6 ? 41 : 4;
	memcpy(o + 12, TEST_POP_IP, 4);
	memcpy(o + 16, origin, 4);
	w16(o + 10, csum_fold16(csum_sum(o, 20)));
	put(e, in->b + l3, in->len - l3);
}

int check_bytes(const char *name, const struct pkt *out, const struct pkt *want)
{
	char why[96];
	size_t i = 0;

	if (out->len != want->len) {
		snprintf(why, sizeof(why), "length %zu, want %zu", out->len, want->len);
		return check(name, 0, why);
	}
	while (i < want->len && out->b[i] == want->b[i])
		i++;
	snprintf(why, sizeof(why), "first difference at byte %zu (got %02x, want %02x)",
		 i, i < out->len ? out->b[i] : 0, i < want->len ? want->b[i] : 0);
	return check(name, i == want->len, why);
}

void add_rule4(int map_fd, uint32_t tenant, const uint8_t addr[4], int len,
	       uint64_t expires_ns)
{
	struct xs_src_key k = { .prefixlen = 32 + len, .tenant = tenant };
	struct xs_rule r = { .expires_ns = expires_ns, .reason = XS_R_MANUAL };

	memcpy(&k.src, addr, 4);
	if (bpf_map_update_elem(map_fd, &k, &r, BPF_ANY))
		die("add_rule4");
}

void add_rule6(int map_fd, uint32_t tenant, const uint8_t addr[16], int len,
	       uint64_t expires_ns)
{
	struct xs_src6_key k = { .prefixlen = 32 + len, .tenant = tenant };
	struct xs_rule r = { .expires_ns = expires_ns, .reason = XS_R_MANUAL };

	memcpy(k.src, addr, 16);
	if (bpf_map_update_elem(map_fd, &k, &r, BPF_ANY))
		die("add_rule6");
}

void add_service_for(uint32_t asset, uint8_t proto, uint16_t port)
{
	struct xs_svc_key k = { .asset = asset, .proto = proto };
	__u8 one = 1;

	w16((uint8_t *)&k.port, port);
	if (bpf_map_update_elem(fd.services, &k, &one, BPF_ANY))
		die("add_service");
}

void add_service(uint8_t proto, uint16_t port)
{
	add_service_for(TEST_ASSET4, proto, port);
	add_service_for(TEST_ASSET6, proto, port);
}

/* Sum of per-CPU counters for (tenant, verdict). */
static struct xs_stats_val read_stat_t(uint32_t tenant, int verdict)
{
	struct xs_stats_key key = { .tenant = tenant, .verdict = verdict };
	struct xs_stats_val *vals = calloc(ncpu, sizeof(*vals));
	struct xs_stats_val sum = { 0 };

	if (!vals)
		die("calloc");
	if (bpf_map_lookup_elem(fd.stats, &key, vals) == 0) {
		for (int i = 0; i < ncpu; i++) {
			sum.pkts += vals[i].pkts;
			sum.bytes += vals[i].bytes;
		}
	}
	free(vals);
	return sum;
}

uint64_t stat_pkts(uint32_t tenant, int verdict)
{
	return read_stat_t(tenant, verdict).pkts;
}

/* Counters of every tenant the tests use (global, default, extra assets). */
static const uint32_t test_tenants[] = { XS_TENANT_GLOBAL, TEST_TENANT, 9 };

static struct xs_stats_val read_stat(int verdict)
{
	struct xs_stats_val sum = { 0 };

	for (size_t i = 0; i < sizeof(test_tenants) / sizeof(test_tenants[0]); i++) {
		struct xs_stats_val v = read_stat_t(test_tenants[i], verdict);

		sum.pkts += v.pkts;
		sum.bytes += v.bytes;
	}
	return sum;
}

int check(const char *name, int ok, const char *why)
{
	runs++;
	if (ok) {
		printf("ok   %s\n", name);
	} else {
		failures++;
		printf("FAIL %s: %s\n", name, why);
	}
	return ok;
}

int expect(const char *name, const struct pkt *p, int want_action,
	   int want_verdict, struct pkt *out)
{
	struct xs_stats_val before[XS_V__COUNT], after[XS_V__COUNT];
	struct pkt tmp;
	struct pkt *o = out ? out : &tmp;
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = p->b,
		    .data_size_in = p->len, .data_out = o->b,
		    .data_size_out = sizeof(o->b), .repeat = 1);
	char why[256] = "";
	int err;

	for (int v = 0; v < XS_V__COUNT; v++)
		before[v] = read_stat(v);

	err = bpf_prog_test_run_opts(fd.prog, &opts);
	o->len = opts.data_size_out;
	if (err) {
		snprintf(why, sizeof(why), "test_run failed: %s", strerror(-err));
		goto out;
	}
	if ((int)opts.retval != want_action) {
		snprintf(why, sizeof(why), "action %s, want %s",
			 action_name(opts.retval), action_name(want_action));
		goto out;
	}
	for (int v = 0; v < XS_V__COUNT; v++) {
		__u64 dp, db, wp, wb;

		after[v] = read_stat(v);
		dp = after[v].pkts - before[v].pkts;
		db = after[v].bytes - before[v].bytes;
		wp = v == want_verdict ? 1 : 0;
		wb = v == want_verdict ? p->len : 0;
		if (dp != wp || db != wb) {
			snprintf(why, sizeof(why),
				 "counter %s: +%llu pkts/+%llu bytes, want +%llu/+%llu",
				 verdict_name(v), (unsigned long long)dp,
				 (unsigned long long)db, (unsigned long long)wp,
				 (unsigned long long)wb);
			goto out;
		}
	}
out:
	{
		char label[160];

		snprintf(label, sizeof(label), "%-40s %s %s", name,
			 action_name(want_action), verdict_name(want_verdict));
		return check(label, why[0] == 0, why);
	}
}

static void parser_suite(void)
{
	size_t n = sizeof(xs_cases) / sizeof(xs_cases[0]);
	struct xs_cfg c = { 0 };

	printf("# parser cases (observe, fragments allowed: valid frames are tunnelled)\n");
	reset_state();
	set_policy(XS_P_ALLOW_FRAG, 0, 0);
	for (size_t i = 0; i < n; i++) {
		struct pkt p = { 0 };

		xs_cases[i].build(&p);
		expect(xs_cases[i].name, &p, xs_cases[i].action,
		       xs_cases[i].verdict, NULL);
	}

	printf("# global observe: malformed frames are counted but passed\n");
	c.flags = XS_CFG_F_OBSERVE;
	set_cfg(&c);
	for (size_t i = 0; i < n; i++) {
		struct pkt p = { 0 };
		char name[64];

		if (xs_cases[i].action != XDP_DROP)
			continue;
		xs_cases[i].build(&p);
		snprintf(name, sizeof(name), "observe/%s", xs_cases[i].name);
		expect(name, &p, XDP_PASS, xs_cases[i].verdict, NULL);
	}
	c.flags = 0;
	set_cfg(&c);
	{
		struct pkt p = { 0 };

		c_ipv4_tcp_truncated(&p);
		expect("observe-off/ipv4_tcp_truncated", &p, XDP_DROP,
		       XS_V_DROP_MALFORMED, NULL);
	}
}

static int map_fd(struct bpf_object *obj, const char *name)
{
	int f = bpf_object__find_map_fd_by_name(obj, name);

	if (f < 0) {
		fprintf(stderr, "map %s missing\n", name);
		exit(2);
	}
	return f;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "build/ebpf/xdp_main.o";
	struct bpf_object *obj;
	struct bpf_program *prog;

	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 2;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load %s failed (verifier log above); are you root?\n", path);
		return 2;
	}
	prog = bpf_object__find_program_by_name(obj, "xs_xdp");
	if (!prog) {
		fprintf(stderr, "program xs_xdp missing in %s\n", path);
		return 2;
	}
	fd.prog = bpf_program__fd(prog);
	fd.cfg = map_fd(obj, "xs_cfg");
	fd.tenants = map_fd(obj, "xs_tenants");
	fd.tenants6 = map_fd(obj, "xs_tenants6");
	fd.stats = map_fd(obj, "xs_stats");
	fd.allow = map_fd(obj, "xs_allow");
	fd.allow6 = map_fd(obj, "xs_allow6");
	fd.block = map_fd(obj, "xs_block");
	fd.block6 = map_fd(obj, "xs_block6");
	fd.services = map_fd(obj, "xs_services");
	fd.rl = map_fd(obj, "xs_rl");
	fd.verified = map_fd(obj, "xs_verified");
	ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0) {
		fprintf(stderr, "libbpf_num_possible_cpus failed\n");
		return 2;
	}

	parser_suite();
	run_policy_tests();
	run_tunnel_tests();

	printf("%d/%d passed\n", runs - failures, runs);
	bpf_object__close(obj);
	return failures ? 1 : 0;
}
