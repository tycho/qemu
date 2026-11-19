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
#include "qemu/units.h"
#include "qemu/bitops.h"
#include "exec/cpu-common.h"

/* log2 of the entries per vCPU; a compile-time constant, overridable. */
#ifndef TB_JMP_CACHE_BITS
#define TB_JMP_CACHE_BITS 16
#endif
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/*
 * The entries' alignment: system mode groups them by guest page
 * (tb-hash.h), and a group of 1024 16-byte entries aligned so is one
 * host page where pages are 16 KiB (four where they are 4 KiB).  COFF
 * can't align to more than 8 KiB; Windows' pages are 4 KiB.
 */
#ifdef _WIN32
#define TB_JMP_CACHE_ALIGN (8 * KiB)
#else
#define TB_JMP_CACHE_ALIGN (16 * KiB)
#endif

/*
 * Invalidated in parallel; all accesses to 'tb' must be atomic.
 * A valid entry is read/written by a single CPU, therefore there is
 * no need for qatomic_rcu_read() and pc is always consistent with a
 * non-NULL value of 'tb'.  Strictly speaking pc is only needed for
 * CF_PCREL, but it's used always for simplicity.
 *
 * With tcg_jc_code, entries hold host code and their TBs are in tbs[]:
 * only the owning vCPU (or a flush, exclusive or on the owner) writes an
 * entry's code and TB, and every access to pc is atomic, since another
 * vCPU's invalidation poisons it (tb_jmp_cache_inval_tb).  A non-NULL TB
 * may then be one invalidated since, beside a pc no lookup matches.
 */
typedef struct CPUJumpCache {
    struct rcu_head rcu;
    /*
     * tcg_jcgen: entries store pc ^ salt, and a flush moves the salt on
     * instead of clearing every entry.  The salt lives in the high bits
     * that the guest's pcs never need to tell two addresses apart, from
     * bit TCGCPUOps.jmp_cache_salt_shift up, and moves on by salt_step.
     * Zero without tcg_jcgen.
     */
    uint64_t salt;
    /*
     * tcg_jcgen: the salt of entries whose code is on a global page (in
     * the TLB, and the TB on one page), which survive a flush of the
     * non-global translations (tcg_flush_jmp_cache_nonglobal).  Bit 63
     * is set in gsalt and clear in salt, so the two never meet.
     */
    uint64_t gsalt;
    /*
     * tcg_jc_ctx: the TB state (cs_base, flags, cflags) every entry under
     * the current salt was made for.  A lookup in another state moves the
     * salt on first, so the generated lookup needn't compare them.
     */
    uint64_t ctx_cs_base;
    uint32_t ctx_flags;
    uint32_t ctx_cflags;
    struct {
        /* The TB; with x-ijlean, its host code (the TB is in tbs[]). */
        union {
            TranslationBlock *tb;
            const void *code;
        };
        vaddr pc;
    } array[TB_JMP_CACHE_SIZE] QEMU_ALIGNED(TB_JMP_CACHE_ALIGN);
    /*
     * tcg_retstack: the return stack's ring, cleared with the cache: its
     * host code is for the TB state of the cache.
     */
    void *retring;
    /* User mode: the mapping that holds it, with its guard pages. */
    void *retmap;
    /*
     * tcg_superblock with edge checks: a request seen at an exit that
     * names no TB (exit_tb(NULL, 0)) samples the next TB the main loop
     * runs instead.
     */
    bool region_sample_next;
    /*
     * tcg_jcgen: 1 << the salt's lowest bit, for the guest mode at the
     * last flush; a flush in a mode with another clears the entries.
     * The key bits below it are the pc's.
     */
    uint64_t salt_step;
#ifndef CONFIG_USER_ONLY
    /*
     * One bit per slot, in the same groups: a page's bit in its group
     * (tb_jmp_cache_filter_bit) is set where an entry for a pc on it is
     * made, and a page clear that scans the group sets the bits again
     * from the entries it keeps.  A clear of a page whose bit is clear
     * skips the scan.  Entries under older salts may be left without
     * their bit; only revalidation, which walks the TB's pages, takes
     * them again.
     */
    unsigned long filter[BITS_TO_LONGS(TB_JMP_CACHE_SIZE)];
#else
    /*
     * tcg_jc_code: each entry's TB, for the C side (the generated probe
     * reads only the entry), TB_JMP_CACHE_SIZE of them; NULL otherwise.
     */
    TranslationBlock **tbs;
#endif
} CPUJumpCache;

#define TB_JMP_GSALT_BASE (1ull << 63)

/*
 * x-ijlean applies (user mode, with tcg_jc_ctx): each entry holds its TB's
 * host code, the TB itself in tbs[]; the generated probe compares the key
 * and branches.  Always false in system mode.
 */
extern bool tcg_jc_code;

/*
 * x-ijlean: a cleared entry's key.  In user mode the generated probe's
 * slot is the pc's low TB_JMP_CACHE_BITS bits, which every key keeps (the
 * salt is above them), so no key looked up at slot @h has these.
 */
static inline vaddr tb_jmp_cache_poison(uint32_t h)
{
    return (vaddr)(h ^ 1);
}

/* The TB of entry @h, or NULL. */
static inline TranslationBlock *tb_jmp_cache_tb(CPUJumpCache *jc, uint32_t h)
{
#ifdef CONFIG_USER_ONLY
    if (tcg_jc_code) {
        return qatomic_read(&jc->tbs[h]);
    }
#endif
    return qatomic_read(&jc->array[h].tb);
}

/*
 * Clear entry @h: no lookup finds a TB there.  On the owning vCPU, or with
 * every vCPU stopped: another vCPU's invalidation only poisons the key.
 */
static inline void tb_jmp_cache_clear(CPUJumpCache *jc, uint32_t h)
{
#ifdef CONFIG_USER_ONLY
    if (tcg_jc_code) {
        qatomic_set(&jc->array[h].pc, tb_jmp_cache_poison(h));
        qatomic_set(&jc->tbs[h], NULL);
        return;
    }
#endif
    qatomic_set(&jc->array[h].tb, NULL);
}

#endif /* ACCEL_TCG_TB_JMP_CACHE_H */
