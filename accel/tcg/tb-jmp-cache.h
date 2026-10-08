/*
 * The per-CPU TranslationBlock jump cache.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_TB_JMP_CACHE_H
#define ACCEL_TCG_TB_JMP_CACHE_H

#include "qemu/rcu.h"
#include "exec/cpu-common.h"

/* log2 of the entries per vCPU; a compile-time constant, overridable. */
#ifndef TB_JMP_CACHE_BITS
#define TB_JMP_CACHE_BITS 18
#endif
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/*
 * Invalidated in parallel; all accesses to 'tb' must be atomic.
 * A valid entry is read/written by a single CPU, therefore there is
 * no need for qatomic_rcu_read() and pc is always consistent with a
 * non-NULL value of 'tb'.  Strictly speaking pc is only needed for
 * CF_PCREL, but it's used always for simplicity.
 */
typedef struct CPUJumpCache {
    struct rcu_head rcu;
    struct {
        TranslationBlock *tb;
        vaddr pc;
    } array[TB_JMP_CACHE_SIZE];
    /*
     * tcg_jcgen: entries store pc ^ salt, and a flush moves the salt on
     * instead of clearing every entry.  The salt lives in bits 48-63,
     * which a guest pc never needs to tell two addresses apart on x86
     * (canonical 64-bit addresses, 32-bit ones otherwise).  Zero without
     * tcg_jcgen.
     */
    uint64_t salt;
    /*
     * tcg_jcgen: the salt of entries whose code is on a global page (in
     * the TLB, and the TB on one page), which survive a flush of the
     * non-global translations (tcg_flush_jmp_cache_nonglobal).  Bit 63
     * is set in gsalt and clear in salt, so the two never meet.
     */
    uint64_t gsalt;
} CPUJumpCache;

#define TB_JMP_SALT_STEP (1ull << 48)
#define TB_JMP_GSALT_BASE (1ull << 63)

#endif /* ACCEL_TCG_TB_JMP_CACHE_H */
