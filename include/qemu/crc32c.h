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
 * crc32c_fast: crc32c(), the same result, with the host's CRC32C
 * instructions when the compiler may use them (aarch64 FEAT_CRC32, x86
 * SSE4.2), the table otherwise.
 */
static inline uint32_t crc32c_fast(uint32_t crc, const void *data,
                                   unsigned int length)
{
#if defined(QEMU_CRC32C_ARM) || defined(QEMU_CRC32C_X86)
    const uint8_t *p = data;

    for (; length >= 8; p += 8, length -= 8) {
        uint64_t v = ldq_le_p(p);

#ifdef QEMU_CRC32C_ARM
        crc = __crc32cd(crc, v);
#else
        crc = _mm_crc32_u64(crc, v);
#endif
    }
    for (; length; p++, length--) {
#ifdef QEMU_CRC32C_ARM
        crc = __crc32cb(crc, *p);
#else
        crc = _mm_crc32_u8(crc, *p);
#endif
    }
    return crc ^ 0xffffffff;
#else
    return crc32c(crc, data, length);
#endif
}

#endif
