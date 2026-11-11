/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * SYN-challenge cookies: SipHash-2-4 keyed with xs_cfg.cookie_key over
 * (source, destination, ports, time slot).
 *
 * Plain C with no BPF helpers, so the C tests compile the exact same code to
 * compute the bytes they expect from the XDP program.
 *
 * The 64-bit hash gives two values for the challenge SYN-ACK:
 *   ack_seq = low 32 bits  (the cookie; the client echoes it as RST.seq)
 *   seq     = high 32 bits (our ISN; never checked, just not predictable)
 */
#ifndef XS_COOKIE_H
#define XS_COOKIE_H

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* 2^34 ns ~= 17.2 s per slot; the current and the previous slot are valid. */
#define XS_COOKIE_SLOT_SHIFT 34
#define XS_SYNACK_WINDOW 1024
#define XS_SYNACK_TTL 64
#define XS_COOKIE_MAX_WORDS 5

#define XS_ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define XS_SIPROUND(v0, v1, v2, v3)                                            \
	do {                                                                   \
		v0 += v1; v1 = XS_ROTL64(v1, 13); v1 ^= v0; v0 = XS_ROTL64(v0, 32); \
		v2 += v3; v3 = XS_ROTL64(v3, 16); v3 ^= v2;                         \
		v0 += v3; v3 = XS_ROTL64(v3, 21); v3 ^= v0;                         \
		v2 += v1; v1 = XS_ROTL64(v1, 17); v1 ^= v2; v2 = XS_ROTL64(v2, 32); \
	} while (0)

/* SipHash-2-4 over n (<= XS_COOKIE_MAX_WORDS) little-endian 64-bit words. */
static __always_inline __u64 xs_siphash24(__u64 k0, __u64 k1, const __u64 *m,
					  int n)
{
	__u64 v0 = 0x736f6d6570736575ULL ^ k0;
	__u64 v1 = 0x646f72616e646f6dULL ^ k1;
	__u64 v2 = 0x6c7967656e657261ULL ^ k0;
	__u64 v3 = 0x7465646279746573ULL ^ k1;
	__u64 b = ((__u64)(n * 8)) << 56;

#ifdef __clang__ /* also compiled by gcc in the C tests */
#pragma unroll
#endif
	for (int i = 0; i < XS_COOKIE_MAX_WORDS; i++) {
		if (i >= n)
			break;
		v3 ^= m[i];
		XS_SIPROUND(v0, v1, v2, v3);
		XS_SIPROUND(v0, v1, v2, v3);
		v0 ^= m[i];
	}
	v3 ^= b;
	XS_SIPROUND(v0, v1, v2, v3);
	XS_SIPROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	XS_SIPROUND(v0, v1, v2, v3);
	XS_SIPROUND(v0, v1, v2, v3);
	XS_SIPROUND(v0, v1, v2, v3);
	XS_SIPROUND(v0, v1, v2, v3);
	return v0 ^ v1 ^ v2 ^ v3;
}

static __always_inline __u32 xs_cookie_slot(__u64 now_ns)
{
	return (__u32)(now_ns >> XS_COOKIE_SLOT_SHIFT);
}

/*
 * Address and port arguments are the raw network-order values exactly as
 * they appear in the packet. From the client's point of view: saddr/sport is
 * the client, daddr/dport the protected service.
 */
static __always_inline __u64 xs_cookie_hash4(const __u64 key[2], __be32 saddr,
					     __be32 daddr, __be16 sport,
					     __be16 dport, __u32 slot)
{
	__u64 m[2];

	m[0] = ((__u64)saddr << 32) | daddr;
	m[1] = ((__u64)sport << 48) | ((__u64)dport << 32) | slot;
	return xs_siphash24(key[0], key[1], m, 2);
}

static __always_inline __u64 xs_cookie_hash6(const __u64 key[2],
					     const __u8 saddr[16],
					     const __u8 daddr[16], __be16 sport,
					     __be16 dport, __u32 slot)
{
	__u64 m[5];

	__builtin_memcpy(&m[0], saddr, 16);
	__builtin_memcpy(&m[2], daddr, 16);
	m[4] = ((__u64)sport << 48) | ((__u64)dport << 32) | slot;
	return xs_siphash24(key[0], key[1], m, 5);
}

/*
 * The ack number we send. It must be *unacceptable* to the client (not its
 * ISN + 1) so that the client answers with RST(seq = this value) and stays in
 * SYN-SENT. A 2^-32 collision is avoided by flipping the low bit; the
 * verifier therefore accepts the cookie with and without that bit flipped.
 */
static __always_inline __u32 xs_challenge_ack(__u64 hash, __u32 client_isn)
{
	__u32 c = (__u32)hash;

	return c == client_isn + 1 ? c ^ 1 : c;
}

static __always_inline int xs_cookie_matches(__u64 hash, __u32 rst_seq)
{
	__u32 c = (__u32)hash;

	return rst_seq == c || rst_seq == (c ^ 1);
}

static __always_inline __u32 xs_challenge_seq(__u64 hash)
{
	return (__u32)(hash >> 32);
}

#endif /* XS_COOKIE_H */
