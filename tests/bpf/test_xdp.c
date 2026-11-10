// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * In-kernel dataplane tests. Loads the compiled XDP object through the real
 * verifier and runs it with BPF_PROG_TEST_RUN on every corpus frame:
 *
 *   1. verifier: the object must load; the verified instruction count is
 *      printed so regressions in verification cost show up in CI logs;
 *   2. verdict: every frame returns XDP_PASS (Phase 0 is observe-only);
 *   3. bytes out: the output frame is byte-identical to the input;
 *   4. counters: exactly the expected slots (tests/common/cases.h) move, each
 *      by one packet and the frame length in bytes; no other slot moves;
 *   5. invariants over the whole run: sum(parse outcomes) == RX and
 *      PASS + DROP + TX + REDIRECT == RX.
 *
 * Requires root (CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN).
 *
 *   test_xdp [path/to/em_xdp.bpf.o]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cases.h"

#define XDP_PASS_RC 2

static int failures;
static int nr_cpus;

static int read_totals(int map_fd, struct em_stats *t)
{
	struct em_stats *percpu = calloc(nr_cpus, sizeof(*percpu));
	__u32 key = 0;
	int err;

	if (!percpu)
		return -ENOMEM;
	err = bpf_map_lookup_elem(map_fd, &key, percpu);
	if (!err) {
		memset(t, 0, sizeof(*t));
		for (int cpu = 0; cpu < nr_cpus; cpu++)
			for (int i = 0; i < EM_CNT_SLOTS; i++) {
				t->c[i].packets += percpu[cpu].c[i].packets;
				t->c[i].bytes += percpu[cpu].c[i].bytes;
			}
	}
	free(percpu);
	return err;
}

static void run_corpus(int prog_fd, int stats_fd)
{
	static uint8_t out[PB_MAX];
	int skipped = 0;

	for (size_t i = 0; i < EM_N_CASES; i++) {
		const struct em_case *c = &em_cases[i];
		struct em_stats before, after;
		uint8_t want[EM_CNT_SLOTS];
		struct pb b;
		int err;

		pb_init(&b);
		c->build(&b);
		memset(out, 0xAA, sizeof(out));
		LIBBPF_OPTS(bpf_test_run_opts, opts,
			.data_in = b.buf,
			.data_size_in = b.len,
			.data_out = out,
			.data_size_out = sizeof(out),
			.repeat = 1,
		);

		if (read_totals(stats_fd, &before))
			exit(2);
		err = bpf_prog_test_run_opts(prog_fd, &opts);
		if (err) {
			/* The kernel refuses test frames shorter than an Ethernet
			 * header (-EINVAL); such frames are covered by the host
			 * tests. */
			if (b.len < 14) {
				skipped++;
				continue;
			}
			fprintf(stderr, "FAIL %-18s test_run: %s\n", c->name, strerror(-err));
			failures++;
			continue;
		}
		if (read_totals(stats_fd, &after))
			exit(2);

		if (opts.retval != XDP_PASS_RC) {
			fprintf(stderr, "FAIL %-18s verdict %u want XDP_PASS\n", c->name, opts.retval);
			failures++;
		}
		if (opts.data_size_out != b.len || memcmp(out, b.buf, b.len)) {
			fprintf(stderr, "FAIL %-18s output frame differs from input (%u vs %u bytes)\n",
				c->name, opts.data_size_out, b.len);
			failures++;
		}

		em_case_expected(c, want);
		for (int s = 0; s < EM_CNT_SLOTS; s++) {
			__u64 dp = after.c[s].packets - before.c[s].packets;
			__u64 db = after.c[s].bytes - before.c[s].bytes;
			__u64 wp = want[s], wb = want[s] ? b.len : 0;

			if (dp != wp || db != wb) {
				fprintf(stderr,
					"FAIL %-18s slot %3d: +%llu pkts +%llu bytes, want +%llu/+%llu\n",
					c->name, s, (unsigned long long)dp, (unsigned long long)db,
					(unsigned long long)wp, (unsigned long long)wb);
				failures++;
			}
		}
	}
	printf("corpus: %zu frames run, %d skipped (shorter than ETH_HLEN)\n",
	       EM_N_CASES - skipped, skipped);
}

static void check_invariants(int stats_fd)
{
	struct em_stats t;
	__u64 parse = 0, verdicts;

	if (read_totals(stats_fd, &t))
		exit(2);
	for (int i = 0; i < EM_PARSE_RC_MAX; i++)
		parse += t.c[EM_CNT_PARSE_BASE + i].packets;
	verdicts = t.c[EM_CNT_VERDICT_PASS].packets + t.c[EM_CNT_VERDICT_DROP].packets +
		   t.c[EM_CNT_VERDICT_TX].packets + t.c[EM_CNT_VERDICT_REDIRECT].packets;
	if (parse != t.c[EM_CNT_RX].packets || verdicts != t.c[EM_CNT_RX].packets ||
	    t.c[EM_CNT_RX].packets == 0) {
		fprintf(stderr, "FAIL invariants: rx=%llu parse_sum=%llu verdict_sum=%llu\n",
			(unsigned long long)t.c[EM_CNT_RX].packets, (unsigned long long)parse,
			(unsigned long long)verdicts);
		failures++;
	} else {
		printf("invariants: rx=%llu == sum(parse outcomes) == sum(verdicts)\n",
		       (unsigned long long)t.c[EM_CNT_RX].packets);
	}
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "build/em_xdp.bpf.o";
	static char vlog[64 * 1024];
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *stats;
	int err;

	if (geteuid() != 0)
		fprintf(stderr, "warning: not running as root; loading will likely fail\n");

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus <= 0) {
		fprintf(stderr, "cannot determine possible CPUs\n");
		return 2;
	}

	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 2;
	}
	prog = bpf_object__find_program_by_name(obj, "em_xdp_main");
	stats = bpf_object__find_map_by_name(obj, "em_stats");
	if (!prog || !stats) {
		fprintf(stderr, "object is missing em_xdp_main/em_stats\n");
		return 2;
	}
	if (bpf_map__value_size(stats) != sizeof(struct em_stats)) {
		fprintf(stderr, "FAIL em_stats value size %u != %zu (ABI drift)\n",
			bpf_map__value_size(stats), sizeof(struct em_stats));
		return 1;
	}

	/* log level 4 = BPF_LOG_STATS: only the summary lines */
	bpf_program__set_log_level(prog, 4);
	bpf_program__set_log_buf(prog, vlog, sizeof(vlog));
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "verifier rejected %s: %s\n%s\n", path, strerror(-err), vlog);
		return 1;
	}
	printf("verifier: accepted, %u BPF insns\n%s", (unsigned)bpf_program__insn_cnt(prog), vlog);

	run_corpus(bpf_program__fd(prog), bpf_map__fd(stats));
	check_invariants(bpf_map__fd(stats));

	bpf_object__close(obj);
	if (failures) {
		printf("xdp tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("xdp tests: OK\n");
	return 0;
}
