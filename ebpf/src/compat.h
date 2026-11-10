/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * compat.h - build-environment shim.
 *
 * The dataplane headers (abi.h, parsers.h, account.h) are compiled in two
 * environments:
 *
 *   1. clang -target bpf (__bpf__ defined): the real XDP object. Types and
 *      helper declarations come from the Linux UAPI headers and libbpf.
 *   2. a normal host C compiler (Linux or macOS): the parser/accounting unit
 *      tests in tests/bpf/parser_host.c and the libbpf test harness. The same
 *      parser code is exercised with malformed input on any developer
 *      machine, without root.
 *
 * Nothing in parsers.h or account.h may call a BPF helper; they only use
 * fixed-width types and byte-order conversion.
 *
 * Phase 0 deliberately does not use vmlinux.h: the parser describes wire
 * formats, not kernel structures, so there is nothing to relocate (see
 * docs/decisions.md, D-003).
 */
#ifndef EM_COMPAT_H
#define EM_COMPAT_H

#if defined(__bpf__)

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#else /* host build */

#include <stdint.h>
#include <stddef.h>

#if defined(__linux__)
#include <linux/types.h>
#else
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint16_t __sum16;
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "host test build assumes a little-endian host"
#endif
#define bpf_htons(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) ((__be32)__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))

#endif /* __bpf__ */

/*
 * Hide a value from the optimiser. Used to keep range masks that are no-ops
 * at runtime but that the verifier needs; without the barrier clang proves
 * the mask redundant and deletes it.
 */
#define em_opaque(x) ({						\
	__typeof__(x) ___v = (x);				\
	asm volatile("" : "+r"(___v));				\
	___v;							\
})

/*
 * Byte-swap a 16-bit wire value and re-establish its [0, 0xFFFF] bound. The
 * verifier does not propagate value ranges through the BPF_END (bswap)
 * instruction, so bpf_ntohs() yields an unbounded scalar that cannot be added
 * to a packet pointer.
 */
#define em_ntohs_bounded(x) (em_opaque((__u32)bpf_ntohs(x)) & 0xFFFF)

#endif /* EM_COMPAT_H */
