/*
 * AArch64 specific SHA-1 acceleration.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef AARCH64_HOST_CRYPTO_SHA1_H
#define AARCH64_HOST_CRYPTO_SHA1_H

#include "host/cpuinfo.h"
#include <arm_neon.h>

#define HAVE_SHA1_ACCEL  likely(cpuinfo & CPUINFO_SHA1)

/*
 * Four SHA-1 rounds with e = 0: state[0..3] = a, b, c, d in and out,
 * wk[i] the message word plus round constant for round i.  f selects the
 * round function: 0 choose, 1 parity, 2 majority.
 */
static inline void sha1_rounds4_accel(uint32_t state[4],
                                      const uint32_t wk[4], unsigned f)
{
    uint32x4_t abcd = vld1q_u32(state);
    uint32x4_t w = vld1q_u32(wk);
    uint32x4_t e = vdupq_n_u32(0);

    switch (f) {
    case 0:
        asm(".arch_extension sha2\n\t"
            "sha1c %q0, %s1, %2.4s" : "+w"(abcd) : "w"(e), "w"(w));
        break;
    case 1:
        asm(".arch_extension sha2\n\t"
            "sha1p %q0, %s1, %2.4s" : "+w"(abcd) : "w"(e), "w"(w));
        break;
    default:
        asm(".arch_extension sha2\n\t"
            "sha1m %q0, %s1, %2.4s" : "+w"(abcd) : "w"(e), "w"(w));
        break;
    }
    vst1q_u32(state, abcd);
}

#endif /* AARCH64_HOST_CRYPTO_SHA1_H */
