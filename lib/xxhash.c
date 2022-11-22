/*
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2012-2016, Yann Collet.
 *
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation. This program is dual-licensed; you may select
 * either version 2 of the GNU General Public License ("GPL") or BSD license
 * ("BSD").
 *
 * You can contact the author at:
 * - xxHash homepage: https://cyan4973.github.io/xxHash/
 * - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

#include <asm/unaligned.h>
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/xxhash.h>
#include <linux/swab.h>

/*-*************************************
 * Macros
 **************************************/
#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))
#define xxh_rotl64(x, r) ((x << r) | (x >> (64 - r)))

#define get_unaligned_le32(x) (*(u32 *)(x))
#define get_unaligned_le64(x) (*(u64 *)(x))

/*-*************************************
 * Constants
 **************************************/
static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

static const uint64_t PRIME64_1 = 11400714785074694791ULL;
static const uint64_t PRIME64_2 = 14029467366897019727ULL;
static const uint64_t PRIME64_3 =  1609587929392839161ULL;
static const uint64_t PRIME64_4 =  9650029242287828579ULL;
static const uint64_t PRIME64_5 =  2870177450012600261ULL;

static __aligned(64) const u8 __xxh3_def_secret[] = {
	0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c,
	0xf7, 0x21, 0xad, 0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb,
	0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e,
	0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
	0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6,
	0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb,
	0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97,
	0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
	0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7,
	0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
	0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64, 0xea, 0xc5, 0xac, 0x83,
	0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
	0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26,
	0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc,
	0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
	0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

/*-**************************
 *  Utils
 ***************************/
void xxh32_copy_state(struct xxh32_state *dst, const struct xxh32_state *src)
{
	memcpy(dst, src, sizeof(*dst));
}
EXPORT_SYMBOL(xxh32_copy_state);

void xxh64_copy_state(struct xxh64_state *dst, const struct xxh64_state *src)
{
	memcpy(dst, src, sizeof(*dst));
}
EXPORT_SYMBOL(xxh64_copy_state);

/*-***************************
 * Simple Hash Functions
 ****************************/
static uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = xxh_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

uint32_t xxh32(const void *input, const size_t len, const uint32_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *b_end = p + len;
	uint32_t h32;

	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;
		uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
		uint32_t v2 = seed + PRIME32_2;
		uint32_t v3 = seed + 0;
		uint32_t v4 = seed - PRIME32_1;

		do {
			v1 = xxh32_round(v1, get_unaligned_le32(p));
			p += 4;
			v2 = xxh32_round(v2, get_unaligned_le32(p));
			p += 4;
			v3 = xxh32_round(v3, get_unaligned_le32(p));
			p += 4;
			v4 = xxh32_round(v4, get_unaligned_le32(p));
			p += 4;
		} while (p <= limit);

		h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
			xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += (uint32_t)len;

	while (p + 4 <= b_end) {
		h32 += get_unaligned_le32(p) * PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}
EXPORT_SYMBOL(xxh32);

static uint64_t xxh64_round(uint64_t acc, const uint64_t input)
{
	acc += input * PRIME64_2;
	acc = xxh_rotl64(acc, 31);
	acc *= PRIME64_1;
	return acc;
}

static uint64_t xxh64_merge_round(uint64_t acc, uint64_t val)
{
	val = xxh64_round(0, val);
	acc ^= val;
	acc = acc * PRIME64_1 + PRIME64_4;
	return acc;
}

uint64_t xxh64(const void *input, const size_t len, const uint64_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *const b_end = p + len;
	uint64_t h64;

	if (len >= 32) {
		const uint8_t *const limit = b_end - 32;
		uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
		uint64_t v2 = seed + PRIME64_2;
		uint64_t v3 = seed + 0;
		uint64_t v4 = seed - PRIME64_1;

		do {
			v1 = xxh64_round(v1, get_unaligned_le64(p));
			p += 8;
			v2 = xxh64_round(v2, get_unaligned_le64(p));
			p += 8;
			v3 = xxh64_round(v3, get_unaligned_le64(p));
			p += 8;
			v4 = xxh64_round(v4, get_unaligned_le64(p));
			p += 8;
		} while (p <= limit);

		h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) +
			xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
		h64 = xxh64_merge_round(h64, v1);
		h64 = xxh64_merge_round(h64, v2);
		h64 = xxh64_merge_round(h64, v3);
		h64 = xxh64_merge_round(h64, v4);

	} else {
		h64  = seed + PRIME64_5;
	}

	h64 += (uint64_t)len;

	while (p + 8 <= b_end) {
		const uint64_t k1 = xxh64_round(0, get_unaligned_le64(p));

		h64 ^= k1;
		h64 = xxh_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
		p += 8;
	}

	if (p + 4 <= b_end) {
		h64 ^= (uint64_t)(get_unaligned_le32(p)) * PRIME64_1;
		h64 = xxh_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
		p += 4;
	}

	while (p < b_end) {
		h64 ^= (*p) * PRIME64_5;
		h64 = xxh_rotl64(h64, 11) * PRIME64_1;
		p++;
	}

	h64 ^= h64 >> 33;
	h64 *= PRIME64_2;
	h64 ^= h64 >> 29;
	h64 *= PRIME64_3;
	h64 ^= h64 >> 32;

	return h64;
}
EXPORT_SYMBOL(xxh64);

static inline u64 xxh64_avalanche(u64 h64)
{
	h64 ^= h64 >> 33;
	h64 *= PRIME64_2;
	h64 ^= h64 >> 29;
	h64 *= PRIME64_3;
	h64 ^= h64 >> 32;
	return h64;
}

static inline u64 xxh3_avalanche(u64 h64)
{
	h64 ^= h64 >> 37;
	h64 *= 0x165667919E3779F9ULL;
	h64 ^= h64 >> 32;
	return h64;
}

static inline u64 xxh3_rrmxmx(u64 h64, u64 len)
{
	/* this mix is inspired by Pelle Evensen's rrmxmx */
	h64 ^= xxh_rotl64(h64, 49) ^ xxh_rotl64(h64, 24);
	h64 *= 0x9FB21C651E98DF25ULL;
	h64 ^= (h64 >> 35) + len;
	h64 *= 0x9FB21C651E98DF25ULL;
	h64 ^= h64 >> 28;
	return h64;
}

typedef struct {
	u64 low64;   /*!< `value & 0xFFFFFFFFFFFFFFFF` */
	u64 high64;  /*!< `value >> 64` */
} u128;

static inline u64 xxh_32x32(u32 x, u32 y)
{
	return (u64)(u32)(x) * (u64)(u32)(y);
}

static u128 xxh_64x64(u64 lhs, u64 rhs)
{
	/*
	 * GCC/Clang __uint128_t method.
	 *
	 * On most 64-bit targets, GCC and Clang define a __uint128_t type.
	 * This is usually the best way as it usually uses a native long 64-bit
	 * multiply, such as MULQ on x86_64 or MUL + UMULH on aarch64.
	 *
	 * Usually.
	 *
	 * Despite being a 32-bit platform, Clang (and emscripten) define this type
	 * despite not having the arithmetic for it. This results in a laggy
	 * compiler builtin call which calculates a full 128-bit multiply.
	 * In that case it is best to use the portable one.
	 * https://github.com/Cyan4973/xxHash/issues/211#issuecomment-515575677
	 */
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__wasm__) \
	&& defined(__SIZEOF_INT128__) \
	|| (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 128)

	__uint128_t product = (__uint128_t)lhs * (__uint128_t)rhs;
	u128 r128 = { (u64)(product), (u64)(product >> 64) };
	return r128;

	/*
	 * MSVC for x64's _umul128 method.
	 *
	 * u64 _umul128(u64 Multiplier, u64 Multiplicand, u64 *HighProduct);
	 *
	 * This compiles to single operand MUL on x64.
	 */
#else
	/*
	 * Portable scalar method. Optimized for 32-bit and 64-bit ALUs.
	 *
	 * This is a fast and simple grade school multiply, which is shown below
	 * with base 10 arithmetic instead of base 0x100000000.
	 *
	 *           9 3 // D2 lhs = 93
	 *         x 7 5 // D2 rhs = 75
	 *     ----------
	 *           1 5 // D2 lo_lo = (93 % 10) * (75 % 10) = 15
	 *         4 5 | // D2 hi_lo = (93 / 10) * (75 % 10) = 45
	 *         2 1 | // D2 lo_hi = (93 % 10) * (75 / 10) = 21
	 *     + 6 3 | | // D2 hi_hi = (93 / 10) * (75 / 10) = 63
	 *     ---------
	 *         2 7 | // D2 cross = (15 / 10) + (45 % 10) + 21 = 27
	 *     + 6 7 | | // D2 upper = (27 / 10) + (45 / 10) + 63 = 67
	 *     ---------
	 *       6 9 7 5 // D4 res = (27 * 10) + (15 % 10) + (67 * 100) = 6975
	 *
	 * The reasons for adding the products like this are:
	 *  1. It avoids manual carry tracking. Just like how
	 *     (9 * 9) + 9 + 9 = 99, the same applies with this for UINT64_MAX.
	 *     This avoids a lot of complexity.
	 *
	 *  2. It hints for, and on Clang, compiles to, the powerful UMAAL
	 *     instruction available in ARM's Digital Signal Processing extension
	 *     in 32-bit ARMv6 and later, which is shown below:
	 *
	 *         void UMAAL(xxh_u32 *RdLo, xxh_u32 *RdHi, xxh_u32 Rn, xxh_u32 Rm)
	 *         {
	 *             u64 product = (u64)*RdLo * (u64)*RdHi + Rn + Rm;
	 *             *RdLo = (xxh_u32)(product & 0xFFFFFFFF);
	 *             *RdHi = (xxh_u32)(product >> 32);
	 *         }
	 *
	 *     This instruction was designed for efficient long multiplication, and
	 *     allows this to be calculated in only 4 instructions at speeds
	 *     comparable to some 64-bit ALUs.
	 *
	 *  3. It isn't terrible on other platforms. Usually this will be a couple
	 *     of 32-bit ADD/ADCs.
	 */

	/* First calculate all of the cross products. */
	u64 lo_lo = xxh_32x32(lhs & 0xFFFFFFFF, rhs & 0xFFFFFFFF);
	u64 hi_lo = xxh_32x32(lhs >> 32,        rhs & 0xFFFFFFFF);
	u64 lo_hi = xxh_32x32(lhs & 0xFFFFFFFF, rhs >> 32);
	u64 hi_hi = xxh_32x32(lhs >> 32,        rhs >> 32);

	/* Now add the products together. These will never overflow. */
	u64 cross = (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi;
	u64 upper = (hi_lo >> 32) + (cross >> 32)        + hi_hi;
	u64 lower = (cross << 32) | (lo_lo & 0xFFFFFFFF);

	u128 r128 = { lower, upper };
	return r128;
#endif
}

static inline u64 xxh_64x64_fold(u64 lhs, u64 rhs)
{
	u128 product = xxh_64x64(lhs, rhs);
	return product.low64 ^ product.high64;
}

static inline u32 xxh3_secret32(size_t off)
{
	return *(u32 *)(__xxh3_def_secret + off);
}

static inline u64 xxh3_secret64(size_t off)
{
	return *(u64 *)(__xxh3_def_secret + off);
}

#if defined(__GNUC__) || defined(__clang__)
#  define XXH_COMPILER_GUARD(var) __asm__ __volatile__("" : "+r" (var))
#else
#  define XXH_COMPILER_GUARD(var) ((void)0)
#endif

static inline u64 xxh3_mix16b(const u8 *input, const u8 *secret, u64 seed64)
{
#if defined(__GNUC__) && !defined(__clang__) /* GCC, not Clang */ \
	&& defined(__i386__) && defined(__SSE2__)  /* x86 + SSE2 */ \
	&& !defined(XXH_ENABLE_AUTOVECTORIZE)      /* Define to disable like XXH32 hack */
	/*
	 * UGLY HACK:
	 * GCC for x86 tends to autovectorize the 128-bit multiply, resulting in
	 * slower code.
	 *
	 * By forcing seed64 into a register, we disrupt the cost model and
	 * cause it to scalarize. See `XXH32_round()`
	 *
	 * FIXME: Clang's output is still _much_ faster -- On an AMD Ryzen 3600,
	 * XXH3_64bits @ len=240 runs at 4.6 GB/s with Clang 9, but 3.3 GB/s on
	 * GCC 9.2, despite both emitting scalar code.
	 *
	 * GCC generates much better scalar code than Clang for the rest of XXH3,
	 * which is why finding a more optimal codepath is an interest.
	 */
	XXH_COMPILER_GUARD(seed64);
#endif
	u64 input_lo = get_unaligned_le64(input);
	u64 input_hi = get_unaligned_le64(input + 8);
	return xxh_64x64_fold(input_lo ^ (xxh3_secret64(0) + seed64),
			      input_hi ^ (xxh3_secret64(8) - seed64));
	
}

u64 xxh3_1_to_3(const void *input, size_t n, u64 seed)
{
	u32 c1 = ((const u8 *)input)[0];
	u32 c2 = ((const u8 *)input)[n >> 1];
	u32 c3 = ((const u8 *)input)[n - 1];
	u32 combined = (c1 << 16) | (c2 << 24) | (c3 << 0) | ((u32)n << 8);
	u64 bitflip = (xxh3_secret32(0) ^ xxh3_secret32(4)) + seed;
	return xxh64_avalanche((u64)combined ^ bitflip);
}

u64 xxh3_4_to_8(const void *input, size_t len, u64 seed)
{
	u32 input1 = get_unaligned_le32(input);
	u32 input2 = get_unaligned_le32(input + len - 4);
	//
	//
	//
	u64 bitflip = (xxh3_secret64(8) ^ xxh3_secret64(16)) - (seed ^ ((u64)swab32(seed) << 32));
	u64 input64 = input2 + (((u64)input1) << 32);
	u64 keyed = input64 ^ bitflip;
	return xxh3_rrmxmx(keyed, len);
}

u64 xxh3_9_to_16(const void* input, size_t len, u64 seed)
{
	u64 bitflip1 = (xxh3_secret64(24) ^ xxh3_secret64(32)) + seed;
	u64 bitflip2 = (xxh3_secret64(40) ^ xxh3_secret64(48)) - seed;
	u64 input_lo = get_unaligned_le64(input) ^ bitflip1;
	u64 input_hi = get_unaligned_le64(input + len - 8) ^ bitflip2;
	u64 acc = len + swab64(input_lo) + input_hi
		      + xxh_64x64_fold(input_lo, input_hi);
	return xxh3_avalanche(acc);
}

static inline u64 xxh3_0_16(const void *input, size_t len, u64 seed)
{
	if (len > 8)
		return xxh3_9_to_16(input, len, seed);

	if (len >= 4)
		return xxh3_4_to_8(input, len, seed);

	if (len)
		return xxh3_1_to_3(input, len, seed);

	return xxh64_avalanche(seed ^ (xxh3_secret64(56) ^ xxh3_secret64(64)));
}

u64 xxh3_17_to_128(const void *input, size_t len, u64 seed)
{
	const u8 *s = __xxh3_def_secret;
	u64 acc = len * PRIME64_1;

	if (len > 32) {
		if (len > 64) {
			if (len > 96) {
				acc += xxh3_mix16b(input + 48, s + 96, seed);
				acc += xxh3_mix16b(input + len - 64, s + 112, seed);
			}
			acc += xxh3_mix16b(input + 32, s + 64, seed);
			acc += xxh3_mix16b(input + len - 48, s + 80, seed);
		}
		acc += xxh3_mix16b(input + 16, s + 32, seed);
		acc += xxh3_mix16b(input + len - 32, s + 48, seed);
	}
	acc += xxh3_mix16b(input + 0, s + 0, seed);
	acc += xxh3_mix16b(input + len - 16, s + 16, seed);

	return xxh3_avalanche(acc);
}

u64 xxh3_129_to_240(const void* input, size_t len, u64 seed)
{
	const size_t start = 3, last = 136 - 7;
	const u8 *s = __xxh3_def_secret;
	u64 acc = len * PRIME64_1;
	int rounds = len / 16;
	int i;

	for (i = 0; i < 8; i++)
		acc += xxh3_mix16b(input + 16*i, s + 16*i, seed);

	acc = xxh3_avalanche(acc);

	for (i = 8; i < rounds; i++)
		acc += xxh3_mix16b(input + 16*i, s + 16*(i - 8) + start, seed);
	acc += xxh3_mix16b(input + len - 16, s + last, seed);

	return xxh3_avalanche(acc);
}

uint64_t xxh3_240(const void *input, size_t len, uint64_t seed)
{
	if (len <= 16)
		return xxh3_0_16(input, len, seed);

	if (len <= 128)
		return xxh3_17_to_128(input, len, seed);

	if (len <= 240)
		return xxh3_129_to_240(input, len, seed);

	return 0;
}
EXPORT_SYMBOL(xxh3_240);

EXPORT_SYMBOL(xxh3_1_to_3);
EXPORT_SYMBOL(xxh3_4_to_8);
EXPORT_SYMBOL(xxh3_9_to_16);
EXPORT_SYMBOL(xxh3_17_to_128);
EXPORT_SYMBOL(xxh3_129_to_240);

/*-**************************************************
 * Advanced Hash Functions
 ***************************************************/
void xxh32_reset(struct xxh32_state *statePtr, const uint32_t seed)
{
	/* use a local state for memcpy() to avoid strict-aliasing warnings */
	struct xxh32_state state;

	memset(&state, 0, sizeof(state));
	state.v1 = seed + PRIME32_1 + PRIME32_2;
	state.v2 = seed + PRIME32_2;
	state.v3 = seed + 0;
	state.v4 = seed - PRIME32_1;
	memcpy(statePtr, &state, sizeof(state));
}
EXPORT_SYMBOL(xxh32_reset);

void xxh64_reset(struct xxh64_state *statePtr, const uint64_t seed)
{
	/* use a local state for memcpy() to avoid strict-aliasing warnings */
	struct xxh64_state state;

	memset(&state, 0, sizeof(state));
	state.v1 = seed + PRIME64_1 + PRIME64_2;
	state.v2 = seed + PRIME64_2;
	state.v3 = seed + 0;
	state.v4 = seed - PRIME64_1;
	memcpy(statePtr, &state, sizeof(state));
}
EXPORT_SYMBOL(xxh64_reset);

int xxh32_update(struct xxh32_state *state, const void *input, const size_t len)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *const b_end = p + len;

	if (input == NULL)
		return -EINVAL;

	state->total_len_32 += (uint32_t)len;
	state->large_len |= (len >= 16) | (state->total_len_32 >= 16);

	if (state->memsize + len < 16) { /* fill in tmp buffer */
		memcpy((uint8_t *)(state->mem32) + state->memsize, input, len);
		state->memsize += (uint32_t)len;
		return 0;
	}

	if (state->memsize) { /* some data left from previous update */
		const uint32_t *p32 = state->mem32;

		memcpy((uint8_t *)(state->mem32) + state->memsize, input,
			16 - state->memsize);

		state->v1 = xxh32_round(state->v1, get_unaligned_le32(p32));
		p32++;
		state->v2 = xxh32_round(state->v2, get_unaligned_le32(p32));
		p32++;
		state->v3 = xxh32_round(state->v3, get_unaligned_le32(p32));
		p32++;
		state->v4 = xxh32_round(state->v4, get_unaligned_le32(p32));
		p32++;

		p += 16-state->memsize;
		state->memsize = 0;
	}

	if (p <= b_end - 16) {
		const uint8_t *const limit = b_end - 16;
		uint32_t v1 = state->v1;
		uint32_t v2 = state->v2;
		uint32_t v3 = state->v3;
		uint32_t v4 = state->v4;

		do {
			v1 = xxh32_round(v1, get_unaligned_le32(p));
			p += 4;
			v2 = xxh32_round(v2, get_unaligned_le32(p));
			p += 4;
			v3 = xxh32_round(v3, get_unaligned_le32(p));
			p += 4;
			v4 = xxh32_round(v4, get_unaligned_le32(p));
			p += 4;
		} while (p <= limit);

		state->v1 = v1;
		state->v2 = v2;
		state->v3 = v3;
		state->v4 = v4;
	}

	if (p < b_end) {
		memcpy(state->mem32, p, (size_t)(b_end-p));
		state->memsize = (uint32_t)(b_end-p);
	}

	return 0;
}
EXPORT_SYMBOL(xxh32_update);

uint32_t xxh32_digest(const struct xxh32_state *state)
{
	const uint8_t *p = (const uint8_t *)state->mem32;
	const uint8_t *const b_end = (const uint8_t *)(state->mem32) +
		state->memsize;
	uint32_t h32;

	if (state->large_len) {
		h32 = xxh_rotl32(state->v1, 1) + xxh_rotl32(state->v2, 7) +
			xxh_rotl32(state->v3, 12) + xxh_rotl32(state->v4, 18);
	} else {
		h32 = state->v3 /* == seed */ + PRIME32_5;
	}

	h32 += state->total_len_32;

	while (p + 4 <= b_end) {
		h32 += get_unaligned_le32(p) * PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}
EXPORT_SYMBOL(xxh32_digest);

int xxh64_update(struct xxh64_state *state, const void *input, const size_t len)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *const b_end = p + len;

	if (input == NULL)
		return -EINVAL;

	state->total_len += len;

	if (state->memsize + len < 32) { /* fill in tmp buffer */
		memcpy(((uint8_t *)state->mem64) + state->memsize, input, len);
		state->memsize += (uint32_t)len;
		return 0;
	}

	if (state->memsize) { /* tmp buffer is full */
		uint64_t *p64 = state->mem64;

		memcpy(((uint8_t *)p64) + state->memsize, input,
			32 - state->memsize);

		state->v1 = xxh64_round(state->v1, get_unaligned_le64(p64));
		p64++;
		state->v2 = xxh64_round(state->v2, get_unaligned_le64(p64));
		p64++;
		state->v3 = xxh64_round(state->v3, get_unaligned_le64(p64));
		p64++;
		state->v4 = xxh64_round(state->v4, get_unaligned_le64(p64));

		p += 32 - state->memsize;
		state->memsize = 0;
	}

	if (p + 32 <= b_end) {
		const uint8_t *const limit = b_end - 32;
		uint64_t v1 = state->v1;
		uint64_t v2 = state->v2;
		uint64_t v3 = state->v3;
		uint64_t v4 = state->v4;

		do {
			v1 = xxh64_round(v1, get_unaligned_le64(p));
			p += 8;
			v2 = xxh64_round(v2, get_unaligned_le64(p));
			p += 8;
			v3 = xxh64_round(v3, get_unaligned_le64(p));
			p += 8;
			v4 = xxh64_round(v4, get_unaligned_le64(p));
			p += 8;
		} while (p <= limit);

		state->v1 = v1;
		state->v2 = v2;
		state->v3 = v3;
		state->v4 = v4;
	}

	if (p < b_end) {
		memcpy(state->mem64, p, (size_t)(b_end-p));
		state->memsize = (uint32_t)(b_end - p);
	}

	return 0;
}
EXPORT_SYMBOL(xxh64_update);

uint64_t xxh64_digest(const struct xxh64_state *state)
{
	const uint8_t *p = (const uint8_t *)state->mem64;
	const uint8_t *const b_end = (const uint8_t *)state->mem64 +
		state->memsize;
	uint64_t h64;

	if (state->total_len >= 32) {
		const uint64_t v1 = state->v1;
		const uint64_t v2 = state->v2;
		const uint64_t v3 = state->v3;
		const uint64_t v4 = state->v4;

		h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) +
			xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
		h64 = xxh64_merge_round(h64, v1);
		h64 = xxh64_merge_round(h64, v2);
		h64 = xxh64_merge_round(h64, v3);
		h64 = xxh64_merge_round(h64, v4);
	} else {
		h64  = state->v3 + PRIME64_5;
	}

	h64 += (uint64_t)state->total_len;

	while (p + 8 <= b_end) {
		const uint64_t k1 = xxh64_round(0, get_unaligned_le64(p));

		h64 ^= k1;
		h64 = xxh_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
		p += 8;
	}

	if (p + 4 <= b_end) {
		h64 ^= (uint64_t)(get_unaligned_le32(p)) * PRIME64_1;
		h64 = xxh_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
		p += 4;
	}

	while (p < b_end) {
		h64 ^= (*p) * PRIME64_5;
		h64 = xxh_rotl64(h64, 11) * PRIME64_1;
		p++;
	}

	h64 ^= h64 >> 33;
	h64 *= PRIME64_2;
	h64 ^= h64 >> 29;
	h64 *= PRIME64_3;
	h64 ^= h64 >> 32;

	return h64;
}
EXPORT_SYMBOL(xxh64_digest);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("xxHash");
