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
	"drop_unverified",
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

void set_cfg(const struct xs_cfg *c)
{
	__u32 zero = 0;

	if (bpf_map_update_elem(fd.cfg, &zero, c, BPF_ANY))
		die("update xs_cfg");
}

void set_policy(uint32_t flags, uint32_t pps, uint32_t burst)
{
	__u32 zero = 0;
	struct xs_policy p = { .flags = flags, .pps_per_src = pps, .burst = burst };

	if (bpf_map_update_elem(fd.policy, &zero, &p, BPF_ANY))
		die("update xs_policy");
}

void reset_state(void)
{
	struct xs_cfg c = { 0 };

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

void add_service(uint8_t proto, uint16_t port)
{
	struct xs_svc_key k = { .asset = 0, .proto = proto };
	__u8 one = 1;

	w16((uint8_t *)&k.port, port);
	if (bpf_map_update_elem(fd.services, &k, &one, BPF_ANY))
		die("add_service");
}

/* Sum of per-CPU counters for (tenant 0, verdict). */
static struct xs_stats_val read_stat(int verdict)
{
	struct xs_stats_key key = { .tenant = XS_TENANT_GLOBAL, .verdict = verdict };
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

	printf("# parser cases (no policy; fragments allowed)\n");
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
	fd.policy = map_fd(obj, "xs_policy");
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

	printf("%d/%d passed\n", runs - failures, runs);
	bpf_object__close(obj);
	return failures ? 1 : 0;
}
