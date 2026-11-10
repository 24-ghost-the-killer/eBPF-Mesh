// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Host-side dataplane tests (no root, no Linux needed): runs the parser
 * (ebpf/src/parsers.h) and the accounting stage (ebpf/src/account.h),
 * compiled for the host, against the shared packet corpus.
 *
 *   1. every corpus frame: parse result and every extracted field;
 *   2. every corpus frame: accounting increments exactly the expected slots
 *      (by one packet and the frame length) and nothing else;
 *   3. truncation fuzz: every prefix of every frame;
 *   4. bit-flip fuzz: random mutations; the parse result must stay in range
 *      and the accounting invariant sum(parse slots) == frames must hold.
 *
 * Built with -fsanitize=address,undefined: frames are copied to the end of an
 * exactly-sized heap buffer, so any read past data_end aborts the test. This
 * complements the verifier: the verifier proves memory safety of the BPF
 * build, these tests prove the parser gives the right answer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "cases.h"
#include "account.h"

static int failures;

#define CHECK_EQ(c, field, got, want)                                              \
	do {                                                                       \
		if ((long)(got) != (long)(want)) {                                 \
			fprintf(stderr, "FAIL %-18s %-10s got %ld want %ld\n",     \
				(c)->name, field, (long)(got), (long)(want));      \
			failures++;                                                \
		}                                                                  \
	} while (0)

/*
 * Parse a copy whose last byte is the last byte of a heap allocation, so ASan
 * catches any read past data_end, then account it into *st. The frame starts
 * NET_IP_ALIGN (2) bytes into the allocation, like a driver's RX buffer, so
 * the IP header is 4-byte aligned and UBSan's alignment check stays
 * meaningful for the wire structs.
 */
#define NET_IP_ALIGN 2
static int parse_exact(const uint8_t *frame, uint32_t len, struct em_pkt *p, struct em_stats *st)
{
	uint8_t *alloc = malloc(NET_IP_ALIGN + len);
	uint8_t *copy = alloc + NET_IP_ALIGN;
	int rc;

	if (!alloc) {
		perror("malloc");
		exit(2);
	}
	memcpy(copy, frame, len);
	memset(p, 0, sizeof(*p));
	rc = em_parse_packet(copy, copy + len, p);
	free(alloc);
	if (st) {
		/* Mirror em_xdp_main(): RX, parse/classification, PASS verdict. */
		em_count(st, EM_CNT_RX, len);
		em_account_parse(st, p, rc, len);
		em_count(st, EM_CNT_VERDICT_PASS, len);
	}
	return rc;
}

static void check_counters(const struct em_case *c, const struct em_stats *st, uint32_t len)
{
	uint8_t want[EM_CNT_SLOTS];

	em_case_expected(c, want);
	for (int i = 0; i < EM_CNT_SLOTS; i++) {
		uint64_t wp = want[i], wb = want[i] ? len : 0;

		if (st->c[i].packets != wp || st->c[i].bytes != wb) {
			fprintf(stderr, "FAIL %-18s slot %3d: %llu pkts %llu bytes, want %llu/%llu\n",
				c->name, i, (unsigned long long)st->c[i].packets,
				(unsigned long long)st->c[i].bytes, (unsigned long long)wp,
				(unsigned long long)wb);
			failures++;
		}
	}
}

static void run_case(const struct em_case *c)
{
	struct em_stats st;
	struct em_pkt p;
	struct pb b;
	int rc;

	memset(&st, 0, sizeof(st));
	pb_init(&b);
	c->build(&b);
	rc = parse_exact(b.buf, b.len, &p, &st);

	CHECK_EQ(c, "rc", rc, c->rc);
	check_counters(c, &st, b.len);
	if (em_rc_is_error(c->rc))
		return;
	CHECK_EQ(c, "l3", p.l3, c->l3);
	CHECK_EQ(c, "vlan_depth", p.vlan_depth, c->vlan_depth);
	if (c->rc == EM_PARSE_NOT_IP || c->rc == EM_PARSE_UNSUP_VLAN_DEPTH)
		return;
	CHECK_EQ(c, "l4_proto", p.l4_proto, c->l4_proto);
	CHECK_EQ(c, "frag", p.frag, c->frag);
	CHECK_EQ(c, "n_ext", p.n_ext, c->n_ext);
	CHECK_EQ(c, "anomalies", p.anomalies, c->anomalies);
	CHECK_EQ(c, "l4_parsed", p.l4_parsed, c->l4_parsed);
	CHECK_EQ(c, "tcp_flags", p.tcp_flags, c->tcp_flags);
	CHECK_EQ(c, "sport", ntohs(p.sport), c->sport);
	CHECK_EQ(c, "dport", ntohs(p.dport), c->dport);
}

/* The corpus must not list a slot twice or an out-of-range slot, and names
 * must be unique (they label failures and the BPF test output). */
static void check_corpus(void)
{
	for (size_t i = 0; i < EM_N_CASES; i++) {
		const struct em_case *c = &em_cases[i];

		for (int k = 0; k < EM_CASE_MAX_COUNTERS && c->counters[k]; k++) {
			if (c->counters[k] >= EM_CNT_PARSE_BASE) {
				fprintf(stderr, "FAIL corpus %s: counter %u is not a class slot\n",
					c->name, c->counters[k]);
				failures++;
			}
			for (int j = 0; j < k; j++)
				if (c->counters[j] == c->counters[k]) {
					fprintf(stderr, "FAIL corpus %s: counter %u listed twice\n",
						c->name, c->counters[k]);
					failures++;
				}
		}
		for (size_t j = 0; j < i; j++)
			if (!strcmp(em_cases[j].name, c->name)) {
				fprintf(stderr, "FAIL corpus: duplicate name %s\n", c->name);
				failures++;
			}
	}
}

static void check_invariants(const char *what, const struct em_stats *st, uint64_t frames)
{
	uint64_t parse = 0;

	for (int i = 0; i < EM_PARSE_RC_MAX; i++)
		parse += st->c[EM_CNT_PARSE_BASE + i].packets;
	for (int i = EM_CNT_PARSE_BASE + EM_PARSE_RC_MAX; i < EM_CNT_SLOTS; i++)
		if (st->c[i].packets) {
			fprintf(stderr, "FAIL %s: unused slot %d was incremented\n", what, i);
			failures++;
		}
	if (st->c[EM_CNT_RX].packets != frames || parse != frames ||
	    st->c[EM_CNT_VERDICT_PASS].packets != frames) {
		fprintf(stderr, "FAIL %s invariants: frames=%llu rx=%llu parse_sum=%llu pass=%llu\n",
			what, (unsigned long long)frames,
			(unsigned long long)st->c[EM_CNT_RX].packets, (unsigned long long)parse,
			(unsigned long long)st->c[EM_CNT_VERDICT_PASS].packets);
		failures++;
	}
}

/* Every prefix of every frame must be classified without reading out of
 * bounds. */
static void fuzz_truncation(void)
{
	static struct em_stats st;
	unsigned long runs = 0;

	for (size_t i = 0; i < EM_N_CASES; i++) {
		struct em_pkt p;
		struct pb b;

		pb_init(&b);
		em_cases[i].build(&b);
		for (uint32_t n = 0; n < b.len; n++) {
			(void)parse_exact(b.buf, n, &p, &st);
			runs++;
		}
	}
	check_invariants("truncation fuzz", &st, runs);
	printf("truncation fuzz: %lu prefixes parsed\n", runs);
}

static void fuzz_bitflips(unsigned iterations)
{
	static struct em_stats st;
	unsigned long seed = 0x5eed;
	unsigned hist[EM_PARSE_RC_MAX] = { 0 };

	for (unsigned it = 0; it < iterations; it++) {
		const struct em_case *c = &em_cases[it % EM_N_CASES];
		struct em_pkt p;
		struct pb b;
		int rc;

		pb_init(&b);
		c->build(&b);
		for (int k = 0; k < 4 && b.len; k++) {
			seed = seed * 6364136223846793005ul + 1442695040888963407ul;
			b.buf[(seed >> 33) % b.len] ^= (uint8_t)(1u << ((seed >> 20) & 7));
		}
		rc = parse_exact(b.buf, b.len, &p, &st);
		if (rc < 0 || rc >= EM_PARSE_RC_MAX) {
			fprintf(stderr, "FAIL bitflip: rc %d out of range\n", rc);
			failures++;
			continue;
		}
		hist[rc]++;
	}
	check_invariants("bitflip fuzz", &st, iterations);
	printf("bitflip fuzz: %u mutated frames, outcomes:", iterations);
	for (int i = 0; i < EM_PARSE_RC_MAX; i++)
		if (hist[i])
			printf(" rc%d=%u", i, hist[i]);
	printf("\n");
}

int main(void)
{
	check_corpus();
	for (size_t i = 0; i < EM_N_CASES; i++)
		run_case(&em_cases[i]);
	printf("corpus: %zu cases (fields + exact counter slots)\n", EM_N_CASES);
	fuzz_truncation();
	fuzz_bitflips(200000);

	if (failures) {
		printf("host dataplane tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("host dataplane tests: OK\n");
	return 0;
}
