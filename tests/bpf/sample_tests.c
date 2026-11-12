// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Step 9: packet sampling into the xs_events ring buffer. Events are read
 * back with libbpf's ring buffer consumer and checked field by field.
 */
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "harness.h"

#define ETH_IP 0x0800
#define ETH_IP6 0x86DD
#define MAX_EVENTS 1024

static struct xs_event events[MAX_EVENTS];
static int nevents;

static int on_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (size == sizeof(struct xs_event) && nevents < MAX_EVENTS)
		memcpy(&events[nevents], data, size);
	nevents++;
	return 0;
}

static struct ring_buffer *rb;

/* Drains the ring buffer; returns the number of events read. */
static int drain(void)
{
	nevents = 0;
	ring_buffer__consume(rb);
	return nevents;
}

static void set_rate(uint32_t rate)
{
	struct xs_cfg c = { .sample_rate = rate };

	set_cfg(&c);
}

static void v4_mapped(uint8_t out[16], const uint8_t a[4])
{
	memset(out, 0, 16);
	out[10] = out[11] = 0xff;
	memcpy(out + 12, a, 4);
}

static void check_event(const char *name, const struct xs_event *e, uint32_t tenant,
			uint32_t asset, const uint8_t src[16], const uint8_t dst[16],
			uint16_t sport, uint16_t dport, uint8_t proto, uint8_t flags,
			int verdict, uint8_t family, size_t len, uint32_t rate)
{
	char why[160] = "";

	if (e->tenant != tenant || e->asset != asset)
		snprintf(why, sizeof(why), "tenant/asset %u/%u", e->tenant, e->asset);
	else if (memcmp(e->src, src, 16) || memcmp(e->dst, dst, 16))
		snprintf(why, sizeof(why), "addresses differ");
	else if (e->sport != htons(sport) || e->dport != htons(dport))
		snprintf(why, sizeof(why), "ports %u/%u", ntohs(e->sport), ntohs(e->dport));
	else if (e->proto != proto || e->tcp_flags != flags)
		snprintf(why, sizeof(why), "proto/flags %u/%u", e->proto, e->tcp_flags);
	else if (e->verdict != verdict || e->family != family)
		snprintf(why, sizeof(why), "verdict/family %u/%u", e->verdict, e->family);
	else if (e->len != len || e->sample_rate != rate || e->ts == 0)
		snprintf(why, sizeof(why), "len/rate/ts %u/%u/%llu", e->len, e->sample_rate,
			 (unsigned long long)e->ts);
	check(name, why[0] == 0, why);
}

void run_sample_tests(void)
{
	uint8_t s4[16], d4[16];
	struct pkt p;
	size_t ip;
	int n;

	printf("# sampling (step 9)\n");
	rb = ring_buffer__new(fd.events, on_event, NULL, NULL);
	if (!rb) {
		check("sample/ring buffer consumer", 0, "ring_buffer__new failed");
		return;
	}
	reset_state();
	drain();
	v4_mapped(s4, SRC4);
	v4_mapped(d4, DST4);

	set_rate(0);
	p = (struct pkt){ 0 };
	eth(&p, ETH_IP);
	ip = ipv4(&p, IPPROTO_UDP, 5, 0);
	udp(&p, 5353, 53, 32);
	fix_ipv4_len(&p, ip);
	expect("sample/rate 0", &p, XDP_TX, XS_V_PASS, NULL);
	n = drain();
	check("sample/rate 0: no events", n == 0, "events emitted");

	set_rate(1);
	expect("sample/rate 1 udp", &p, XDP_TX, XS_V_PASS, NULL);
	n = drain();
	if (check("sample/rate 1: one event", n == 1, "not exactly one event"))
		check_event("sample/ipv4 event fields", &events[0], TEST_TENANT, TEST_ASSET4,
			    s4, d4, 5353, 53, IPPROTO_UDP, 0, XS_V_PASS, 4, p.len, 1);

	p = (struct pkt){ 0 };
	eth(&p, ETH_IP6);
	ip = ipv6(&p, IPPROTO_TCP);
	tcp(&p, 40000, 443, TCP_SYN, 5);
	fix_ipv6_len(&p, ip);
	expect("sample/ipv6 syn", &p, XDP_TX, XS_V_PASS, NULL);
	if (drain() == 1)
		check_event("sample/ipv6 event fields", &events[0], TEST_TENANT, TEST_ASSET6,
			    SRC6, DST6, 40000, 443, IPPROTO_TCP, TCP_SYN, XS_V_PASS, 6, p.len, 1);
	else
		check("sample/ipv6 event", 0, "no event");

	/* Drops are sampled too: workers must see attack traffic. */
	set_policy(XS_P_MITIGATE | XS_P_SERVICES, 0, 0);
	p = (struct pkt){ 0 };
	eth(&p, ETH_IP);
	ip = ipv4(&p, IPPROTO_UDP, 5, 0);
	udp(&p, 5353, 53, 32);
	fix_ipv4_len(&p, ip);
	expect("sample/dropped packet", &p, XDP_DROP, XS_V_DROP_SERVICE, NULL);
	if (drain() == 1)
		check_event("sample/drop event fields", &events[0], TEST_TENANT, TEST_ASSET4,
			    s4, d4, 5353, 53, IPPROTO_UDP, 0, XS_V_DROP_SERVICE, 4, p.len, 1);
	else
		check("sample/drop event", 0, "no event");

	/* Malformed and non-IP frames are not sampled. */
	p = (struct pkt){ 0 };
	eth(&p, ETH_IP);
	ip = ipv4(&p, IPPROTO_TCP, 5, 0);
	put(&p, NULL, 10);
	fix_ipv4_len(&p, ip);
	expect("sample/malformed", &p, XDP_DROP, XS_V_DROP_MALFORMED, NULL);
	p = (struct pkt){ 0 };
	eth(&p, 0x0806);
	put(&p, NULL, 28);
	expect("sample/arp", &p, XDP_PASS, XS_V_PASS_NON_IP, NULL);
	check("sample/malformed and non-IP not sampled", drain() == 0, "events emitted");

	/* 1 in 4: 400 packets give about 100 events. */
	set_policy(0, 0, 0);
	set_rate(4);
	p = (struct pkt){ 0 };
	eth(&p, ETH_IP);
	ip = ipv4(&p, IPPROTO_UDP, 5, 0);
	udp(&p, 5353, 53, 32);
	fix_ipv4_len(&p, ip);
	{
		LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = p.b, .data_size_in = p.len,
			    .repeat = 400);
		char why[64];

		bpf_prog_test_run_opts(fd.prog, &opts);
		n = drain();
		snprintf(why, sizeof(why), "%d events for 400 packets at 1/4", n);
		check("sample/rate 4 is about 1 in 4", n >= 50 && n <= 150, why);
		check("sample/rate recorded in events", n > 0 && events[0].sample_rate == 4,
		      "sample_rate field");
	}
	set_rate(0);
	ring_buffer__free(rb);
	reset_state();
}
