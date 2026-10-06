/*
 * No host specific SHA-1 acceleration.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GENERIC_HOST_CRYPTO_SHA1_H
#define GENERIC_HOST_CRYPTO_SHA1_H

#define HAVE_SHA1_ACCEL  false

void sha1_rounds4_accel(uint32_t state[4], const uint32_t wk[4], unsigned f)
    QEMU_ERROR("unsupported accel");

#endif /* GENERIC_HOST_CRYPTO_SHA1_H */
