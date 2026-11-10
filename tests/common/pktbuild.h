/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Tiny frame builder for BPF tests. Writes raw bytes (network order) so the
 * tests do not depend on how the kernel headers lay out structs.
 *
 * Typical use:
 *   struct pkt p = {0};
 *   eth(&p, 0x0800);
 *   size_t ip = ipv4(&p, IPPROTO_TCP, 5, 0);
 *   tcp(&p, 40000, 443, TCP_SYN, 5);
 *   fix_ipv4_len(&p, ip);
 */
#ifndef XS_PKTBUILD_H
#define XS_PKTBUILD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#define PKT_MAX 1024

struct pkt {
	uint8_t b[PKT_MAX];
	size_t len;
};

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

/* Lab addresses (spec section 11.1): bot -> protected IP. */
static const uint8_t SRC4[4] = { 203, 0, 113, 7 };
static const uint8_t DST4[4] = { 198, 51, 100, 10 };
static const uint8_t SRC6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0,
				  0,    0,    0,    0,    0,    0,    0, 7 };
static const uint8_t DST6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0,
				  0,    0,    0,    0,    0,    0,    0, 0x10 };

static inline uint8_t *put(struct pkt *p, const void *src, size_t n)
{
	uint8_t *at = p->b + p->len;

	assert(p->len + n <= PKT_MAX);
	if (src)
		memcpy(at, src, n);
	else
		memset(at, 0, n);
	p->len += n;
	return at;
}

static inline void w16(uint8_t *at, uint16_t v)
{
	at[0] = v >> 8;
	at[1] = v & 0xff;
}

static inline void w32(uint8_t *at, uint32_t v)
{
	w16(at, v >> 16);
	w16(at + 2, v & 0xffff);
}

static inline void eth(struct pkt *p, uint16_t proto)
{
	static const uint8_t dst[6] = { 0x02, 0, 0, 0, 0, 0x02 };
	static const uint8_t src[6] = { 0x02, 0, 0, 0, 0, 0x01 };

	put(p, dst, 6);
	put(p, src, 6);
	w16(put(p, NULL, 2), proto);
}

/* A VLAN tag; the previous ethertype must be 0x8100 or 0x88a8. */
static inline void vlan(struct pkt *p, uint16_t vid, uint16_t next_proto)
{
	uint8_t *h = put(p, NULL, 4);

	w16(h, vid & 0x0fff);
	w16(h + 2, next_proto);
}

/* IPv4 header with ihl 32-bit words (options are NOPs). Returns its offset. */
static inline size_t ipv4(struct pkt *p, uint8_t proto, uint8_t ihl,
			  uint16_t frag_off)
{
	size_t off = p->len;
	uint8_t *h = put(p, NULL, (size_t)ihl * 4);

	h[0] = 0x40 | (ihl & 0x0f);
	w16(h + 2, ihl * 4); /* fixed up by fix_ipv4_len() */
	w16(h + 4, 0x1234);
	w16(h + 6, frag_off);
	h[8] = 64;
	h[9] = proto;
	memcpy(h + 12, SRC4, 4);
	memcpy(h + 16, DST4, 4);
	for (size_t i = 20; i < (size_t)ihl * 4; i++)
		h[i] = 0x01; /* IPOPT_NOOP */
	return off;
}

static inline void fix_ipv4_len(struct pkt *p, size_t ip_off)
{
	w16(p->b + ip_off + 2, p->len - ip_off);
}

/* IPv6 header. Returns its offset. */
static inline size_t ipv6(struct pkt *p, uint8_t nexthdr)
{
	size_t off = p->len;
	uint8_t *h = put(p, NULL, 40);

	h[0] = 0x60;
	h[6] = nexthdr;
	h[7] = 64;
	memcpy(h + 8, SRC6, 16);
	memcpy(h + 24, DST6, 16);
	return off;
}

static inline void fix_ipv6_len(struct pkt *p, size_t ip_off)
{
	w16(p->b + ip_off + 4, p->len - ip_off - 40);
}

/* Generic extension header (HOP/ROUTING/DEST) of (hdrlen + 1) * 8 bytes. */
static inline void ext6(struct pkt *p, uint8_t next, uint8_t hdrlen)
{
	uint8_t *h = put(p, NULL, ((size_t)hdrlen + 1) * 8);

	h[0] = next;
	h[1] = hdrlen;
	h[2] = 0x01; /* PadN option so the header is well formed */
	h[3] = (uint8_t)(((size_t)hdrlen + 1) * 8 - 4);
}

/* IPv6 fragment header; offset in 8-byte units. */
static inline void frag6(struct pkt *p, uint8_t next, uint16_t offset, int mf)
{
	uint8_t *h = put(p, NULL, 8);

	h[0] = next;
	w16(h + 2, (uint16_t)(offset << 3) | (mf ? 1 : 0));
	w32(h + 4, 0xdeadbeef);
}

static inline void tcp(struct pkt *p, uint16_t sport, uint16_t dport,
		       uint8_t flags, uint8_t doff)
{
	uint8_t *h = put(p, NULL, (size_t)doff * 4);

	w16(h, sport);
	w16(h + 2, dport);
	w32(h + 4, 1000);
	h[12] = doff << 4;
	h[13] = flags;
	w16(h + 14, 64240);
}

static inline void udp(struct pkt *p, uint16_t sport, uint16_t dport,
		       size_t payload)
{
	uint8_t *h = put(p, NULL, 8);

	w16(h, sport);
	w16(h + 2, dport);
	w16(h + 4, 8 + payload);
	put(p, NULL, payload);
}

/* ICMP / ICMPv6 echo request header (8 bytes). */
static inline void icmp_echo(struct pkt *p, int v6)
{
	uint8_t *h = put(p, NULL, 8);

	h[0] = v6 ? 128 : 8;
	w16(h + 4, 1);
	w16(h + 6, 1);
}

#endif /* XS_PKTBUILD_H */
