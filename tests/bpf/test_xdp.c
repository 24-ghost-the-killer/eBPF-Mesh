// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * BPF_PROG_TEST_RUN tests for the XDP program.
 *
 * For every case in cases.h: run the crafted frame through the real, verified
 * program and check (1) the XDP action, (2) that exactly one packet with the
 * frame's length was counted, under the expected (tenant 0, verdict) key and
 * nowhere else.
 *
 * Usage: test_xdp <path/to/xdp_main.o>      (needs root / CAP_BPF)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cases.h"

static int prog_fd, stats_fd, cfg_fd, ncpu;
static int failures, runs;

static const char *verdict_name(int v)
{
	switch (v) {
	case XS_V_PASS: return "pass";
	case XS_V_DROP_MALFORMED: return "drop_malformed";
	case XS_V_PASS_NON_IP: return "pass_non_ip";
	case XS_V_FRAGMENT: return "fragment";
	default: return "?";
	}
}

static const char *action_name(int a)
{
	return a == XDP_PASS ? "XDP_PASS" : a == XDP_DROP ? "XDP_DROP" :
	       a == XDP_TX ? "XDP_TX" : "other";
}

/* Sum of per-CPU counters for (tenant 0, verdict). */
static struct xs_stats_val read_stat(int verdict)
{
	struct xs_stats_key key = { .tenant = XS_TENANT_GLOBAL, .verdict = verdict };
	struct xs_stats_val *vals = calloc(ncpu, sizeof(*vals));
	struct xs_stats_val sum = { 0 };

	if (!vals) {
		perror("calloc");
		exit(2);
	}
	if (bpf_map_lookup_elem(stats_fd, &key, vals) == 0) {
		for (int i = 0; i < ncpu; i++) {
			sum.pkts += vals[i].pkts;
			sum.bytes += vals[i].bytes;
		}
	}
	free(vals);
	return sum;
}

static void set_flags(__u32 flags)
{
	__u32 zero = 0;
	struct xs_cfg cfg = { .flags = flags };

	if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY)) {
		perror("update xs_cfg");
		exit(2);
	}
}

static void run_case(const char *name, const struct pkt *p, int want_action,
		     int want_verdict)
{
	struct xs_stats_val before[XS_V__COUNT], after[XS_V__COUNT];
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = p->b,
		    .data_size_in = p->len, .repeat = 1);
	char why[256] = "";
	int err;

	runs++;
	for (int v = 0; v < XS_V__COUNT; v++)
		before[v] = read_stat(v);

	err = bpf_prog_test_run_opts(prog_fd, &opts);
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
	if (why[0]) {
		failures++;
		printf("FAIL %-32s %s\n", name, why);
	} else {
		printf("ok   %-32s %s %s (%zu bytes)\n", name,
		       action_name(want_action), verdict_name(want_verdict),
		       p->len);
	}
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "build/ebpf/xdp_main.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	size_t n = sizeof(xs_cases) / sizeof(xs_cases[0]);

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
	prog_fd = prog ? bpf_program__fd(prog) : -1;
	stats_fd = bpf_object__find_map_fd_by_name(obj, "xs_stats");
	cfg_fd = bpf_object__find_map_fd_by_name(obj, "xs_cfg");
	ncpu = libbpf_num_possible_cpus();
	if (prog_fd < 0 || stats_fd < 0 || cfg_fd < 0 || ncpu <= 0) {
		fprintf(stderr, "program or maps missing in %s\n", path);
		return 2;
	}

	printf("# parser cases (mitigate mode)\n");
	set_flags(0);
	for (size_t i = 0; i < n; i++) {
		struct pkt p = { 0 };

		xs_cases[i].build(&p);
		run_case(xs_cases[i].name, &p, xs_cases[i].action,
			 xs_cases[i].verdict);
	}

	printf("# observe mode: malformed frames are counted but passed\n");
	set_flags(XS_CFG_F_OBSERVE);
	for (size_t i = 0; i < n; i++) {
		struct pkt p = { 0 };
		char name[64];

		if (xs_cases[i].action != XDP_DROP)
			continue;
		xs_cases[i].build(&p);
		snprintf(name, sizeof(name), "observe/%s", xs_cases[i].name);
		run_case(name, &p, XDP_PASS, xs_cases[i].verdict);
	}
	set_flags(0);

	printf("# observe flag cleared: drops again\n");
	{
		struct pkt p = { 0 };

		c_ipv4_tcp_truncated(&p);
		run_case("mitigate/ipv4_tcp_truncated", &p, XDP_DROP,
			 XS_V_DROP_MALFORMED);
	}

	printf("%d/%d passed\n", runs - failures, runs);
	bpf_object__close(obj);
	return failures ? 1 : 0;
}
