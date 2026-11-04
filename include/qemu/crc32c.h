/*
 *  Castagnoli CRC32C Checksum Algorithm
 *
 *  Polynomial: 0x11EDC6F41
 *
 *  Castagnoli93: Guy Castagnoli and Stefan Braeuer and Martin Herrman
 *               "Optimization of Cyclic Redundancy-Check Codes with 24
 *                 and 32 Parity Bits",IEEE Transactions on Communication,
 *                Volume 41, Number 6, June 1993
 *
 *  Copyright (c) 2013 Red Hat, Inc.,
 *
 *  Authors:
 *   Jeff Cody <jcody@redhat.com>
 *
 *  Based on the Linux kernel cryptographic crc32c module,
 *
 *  Copyright (c) 2004 Cisco Systems, Inc.
 *  Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef QEMU_CRC32C_H
#define QEMU_CRC32C_H

#include "qemu/bswap.h"

extern const uint32_t crc32c_table[256];

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);
uint32_t iov_crc32c(uint32_t crc, const struct iovec *iov, size_t iov_cnt);

#if (defined(__aarch64__) || defined(__arm64ec__)) && \
    defined(__ARM_FEATURE_CRC32)
#define QEMU_CRC32C_ARM 1
#include <arm_acle.h>
#elif defined(__x86_64__) && defined(__SSE4_2__)
#define QEMU_CRC32C_X86 1
#include <nmmintrin.h>
#endif

/*
 * One CRC32C update step of 1, 2, 4 or 8 little-endian bytes, without the
 * initial or final complement: the hardware instruction where the
 * compiler targets it, the table otherwise.
 */
static inline uint32_t crc32c_sw(uint32_t crc, uint64_t v, int bytes)
{
    for (int i = 0; i < bytes; i++, v >>= 8) {
        crc = crc32c_table[(crc ^ v) & 0xff] ^ (crc >> 8);
    }
    return crc;
}

static inline uint32_t crc32c_u8(uint32_t crc, uint8_t v)
{
#if defined(QEMU_CRC32C_ARM)
    return __crc32cb(crc, v);
#elif defined(QEMU_CRC32C_X86)
    return _mm_crc32_u8(crc, v);
#else
    return crc32c_sw(crc, v, 1);
#endif
}

static inline uint32_t crc32c_u16(uint32_t crc, uint16_t v)
{
#if defined(QEMU_CRC32C_ARM)
    return __crc32ch(crc, v);
#elif defined(QEMU_CRC32C_X86)
    return _mm_crc32_u16(crc, v);
#else
    return crc32c_sw(crc, v, 2);
#endif
}

static inline uint32_t crc32c_u32(uint32_t crc, uint32_t v)
{
#if defined(QEMU_CRC32C_ARM)
    return __crc32cw(crc, v);
#elif defined(QEMU_CRC32C_X86)
    return _mm_crc32_u32(crc, v);
#else
    return crc32c_sw(crc, v, 4);
#endif
}

static inline uint32_t crc32c_u64(uint32_t crc, uint64_t v)
{
#if defined(QEMU_CRC32C_ARM)
    return __crc32cd(crc, v);
#elif defined(QEMU_CRC32C_X86)
    return _mm_crc32_u64(crc, v);
#else
    return crc32c_sw(crc, v, 8);
#endif
}

#endif
