/*
 * XXH3, 64-bit: xxHash's hash for inputs of any length
 *
 * Ported from xxHash 0.8 (https://github.com/Cyan4973/xxHash)
 * Copyright (C) 2012-2023 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
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
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Only XXH3_64bits() with the default secret and seed 0.  Inputs up to
 * 240 bytes take scalar paths; longer ones accumulate 64-byte stripes in
 * eight 64-bit lanes, six of them with Advanced SIMD on AArch64 hosts.
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "qemu/host-utils.h"
#include "qemu/xxh3.h"

#ifdef HOST_AARCH64
#include <arm_neon.h>
#define XXH3_NEON 1
#endif

#define XXH_PRIME32_1 0x9E3779B1U
#define XXH_PRIME32_2 0x85EBCA77U
#define XXH_PRIME32_3 0xC2B2AE3DU
#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL
#define XXH_PRIME_MX1 0x165667919E3779F9ULL
#define XXH_PRIME_MX2 0x9FB21C651E98DF25ULL

#define XXH3_SECRET_SIZE 192
#define XXH3_STRIPE_LEN 64
/* A block: as many stripes as the secret has 8-byte steps after one. */
#define XXH3_BLOCK_STRIPES ((XXH3_SECRET_SIZE - XXH3_STRIPE_LEN) / 8)
#define XXH3_BLOCK_LEN (XXH3_STRIPE_LEN * XXH3_BLOCK_STRIPES)

static const uint8_t xxh3_secret[XXH3_SECRET_SIZE] QEMU_ALIGNED(64) = {
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

static inline uint64_t sec64(size_t off)
{
    return ldq_le_p(xxh3_secret + off);
}

/* The 128-bit product's halves XORed together. */
static inline uint64_t mul128_fold64(uint64_t a, uint64_t b)
{
    uint64_t lo, hi;

    mulu64(&lo, &hi, a, b);
    return lo ^ hi;
}

static inline uint64_t xxh64_avalanche(uint64_t h)
{
    h ^= h >> 33;
    h *= XXH_PRIME64_2;
    h ^= h >> 29;
    h *= XXH_PRIME64_3;
    return h ^ (h >> 32);
}

static inline uint64_t xxh3_avalanche(uint64_t h)
{
    h ^= h >> 37;
    h *= XXH_PRIME_MX1;
    return h ^ (h >> 32);
}

static inline uint64_t xxh3_rrmxmx(uint64_t h, uint64_t len)
{
    h ^= rol64(h, 49) ^ rol64(h, 24);
    h *= XXH_PRIME_MX2;
    h ^= (h >> 35) + len;
    h *= XXH_PRIME_MX2;
    return h ^ (h >> 28);
}

static uint64_t xxh3_len_0to16(const uint8_t *p, size_t len)
{
    if (len > 8) {
        uint64_t lo = ldq_le_p(p) ^ sec64(24) ^ sec64(32);
        uint64_t hi = ldq_le_p(p + len - 8) ^ sec64(40) ^ sec64(48);

        return xxh3_avalanche(len + bswap64(lo) + hi + mul128_fold64(lo, hi));
    }
    if (len >= 4) {
        uint64_t in = (uint32_t)ldl_le_p(p + len - 4) +
                      ((uint64_t)(uint32_t)ldl_le_p(p) << 32);

        return xxh3_rrmxmx(in ^ sec64(8) ^ sec64(16), len);
    }
    if (len) {
        uint32_t c = ((uint32_t)p[0] << 16) | ((uint32_t)p[len >> 1] << 24) |
                     p[len - 1] | ((uint32_t)len << 8);
        uint32_t flip = ldl_le_p(xxh3_secret) ^ ldl_le_p(xxh3_secret + 4);

        return xxh64_avalanche((uint64_t)c ^ flip);
    }
    return xxh64_avalanche(sec64(56) ^ sec64(64));
}

static inline uint64_t xxh3_mix16(const uint8_t *p, size_t sec)
{
    return mul128_fold64(ldq_le_p(p) ^ sec64(sec),
                         ldq_le_p(p + 8) ^ sec64(sec + 8));
}

static uint64_t xxh3_len_17to128(const uint8_t *p, size_t len)
{
    uint64_t acc = len * XXH_PRIME64_1;

    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc += xxh3_mix16(p + 48, 96);
                acc += xxh3_mix16(p + len - 64, 112);
            }
            acc += xxh3_mix16(p + 32, 64);
            acc += xxh3_mix16(p + len - 48, 80);
        }
        acc += xxh3_mix16(p + 16, 32);
        acc += xxh3_mix16(p + len - 32, 48);
    }
    acc += xxh3_mix16(p, 0);
    acc += xxh3_mix16(p + len - 16, 16);
    return xxh3_avalanche(acc);
}

static uint64_t xxh3_len_129to240(const uint8_t *p, size_t len)
{
    uint64_t acc = len * XXH_PRIME64_1, acc_end;
    unsigned rounds = len / 16;

    for (unsigned i = 0; i < 8; i++) {
        acc += xxh3_mix16(p + 16 * i, 16 * i);
    }
    /* The last 16 bytes, at secret offset 136 - 17. */
    acc_end = xxh3_mix16(p + len - 16, 119);
    acc = xxh3_avalanche(acc);
    for (unsigned i = 8; i < rounds; i++) {
        acc_end += xxh3_mix16(p + 16 * i, 16 * (i - 8) + 3);
    }
    return xxh3_avalanche(acc + acc_end);
}

#ifdef XXH3_NEON
/* Lanes 2j and 2j + 1's sums for one stripe, independent of the lanes. */
static inline uint64x2_t xxh3_neon_sum(uint64x2_t d, uint64x2_t k)
{
    uint64x2_t dk = veorq_u64(d, k);

    return vmlal_u32(vextq_u64(d, d, 1), vmovn_u64(dk), vshrn_n_u64(dk, 32));
}

static inline uint64x2_t xxh3_ld(const uint8_t *p)
{
    return vreinterpretq_u64_u8(vld1q_u8(p));
}
#endif

/*
 * @n stripes from @p into the lanes @acc, the secret advancing 8 bytes a
 * stripe from @sec.  Each lane takes the 32x32-bit product of its input
 * word XOR the secret's halves; its neighbour takes the input word itself.
 */
static void xxh3_stripes(uint64_t *acc, const uint8_t *p, size_t sec,
                         size_t n)
{
#ifdef XXH3_NEON
    /*
     * Lanes 0-5 in vectors, 6 and 7 in general registers, so that both
     * kinds of pipeline work.
     */
    uint64x2_t a[3];

    for (int j = 0; j < 3; j++) {
        a[j] = vld1q_u64(acc + 2 * j);
    }
    for (size_t s = 0; s < n; s++, p += XXH3_STRIPE_LEN, sec += 8) {
        const uint8_t *k = xxh3_secret + sec;
        uint64x2_t s0, s1, s2;

        s0 = xxh3_neon_sum(xxh3_ld(p), xxh3_ld(k));
        s1 = xxh3_neon_sum(xxh3_ld(p + 16), xxh3_ld(k + 16));
        s2 = xxh3_neon_sum(xxh3_ld(p + 32), xxh3_ld(k + 32));
        /*
         * Keep the compiler from folding the multiplies into the
         * accumulators, which would put their latency on the loop's
         * dependency.
         */
        asm("" : "+w"(s0), "+w"(s1), "+w"(s2));
        a[0] = vaddq_u64(a[0], s0);
        a[1] = vaddq_u64(a[1], s1);
        a[2] = vaddq_u64(a[2], s2);
        for (int i = 6; i < 8; i++) {
            uint64_t d = ldq_le_p(p + 8 * i);
            uint64_t dk = d ^ ldq_le_p(k + 8 * i);

            acc[i ^ 1] += d;
            acc[i] += (uint64_t)(uint32_t)dk * (dk >> 32);
        }
    }
    for (int j = 0; j < 3; j++) {
        vst1q_u64(acc + 2 * j, a[j]);
    }
#else
    for (size_t s = 0; s < n; s++, p += XXH3_STRIPE_LEN, sec += 8) {
        for (int i = 0; i < 8; i++) {
            uint64_t d = ldq_le_p(p + 8 * i);
            uint64_t dk = d ^ sec64(sec + 8 * i);

            acc[i ^ 1] += d;
            acc[i] += (uint64_t)(uint32_t)dk * (dk >> 32);
        }
    }
#endif
}

static void xxh3_scramble(uint64_t *acc)
{
    for (int i = 0; i < 8; i++) {
        uint64_t a = acc[i];

        a ^= a >> 47;
        a ^= sec64(XXH3_SECRET_SIZE - XXH3_STRIPE_LEN + 8 * i);
        acc[i] = a * XXH_PRIME32_1;
    }
}

static uint64_t xxh3_long(const uint8_t *p, size_t len)
{
    uint64_t acc[8] QEMU_ALIGNED(16) = {
        XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3,
        XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1,
    };
    size_t blocks = (len - 1) / XXH3_BLOCK_LEN;
    uint64_t h = len * XXH_PRIME64_1;

    for (size_t b = 0; b < blocks; b++) {
        xxh3_stripes(acc, p + b * XXH3_BLOCK_LEN, 0, XXH3_BLOCK_STRIPES);
        xxh3_scramble(acc);
    }
    xxh3_stripes(acc, p + blocks * XXH3_BLOCK_LEN, 0,
                 (len - 1 - blocks * XXH3_BLOCK_LEN) / XXH3_STRIPE_LEN);
    /* The last stripe, at secret offset 192 - 64 - 7. */
    xxh3_stripes(acc, p + len - XXH3_STRIPE_LEN, 121, 1);

    /* The lanes merged, the secret from offset 11. */
    for (int i = 0; i < 4; i++) {
        h += mul128_fold64(acc[2 * i] ^ sec64(11 + 16 * i),
                           acc[2 * i + 1] ^ sec64(11 + 16 * i + 8));
    }
    return xxh3_avalanche(h);
}

uint64_t qemu_xxh3_64(const void *data, size_t len)
{
    const uint8_t *p = data;

    if (len <= 16) {
        return xxh3_len_0to16(p, len);
    }
    if (len <= 128) {
        return xxh3_len_17to128(p, len);
    }
    if (len <= 240) {
        return xxh3_len_129to240(p, len);
    }
    return xxh3_long(p, len);
}
