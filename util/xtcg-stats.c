/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xtcg Phase-1 event counters (development aid, not for upstream).
 * See include/qemu/xtcg-stats.h.
 */

#include "qemu/osdep.h"
#include "qemu/xtcg-stats.h"

bool xtcg_stats;
uint64_t xtcg_stat[XS__COUNT];
uint64_t xtcg_hist[XH__COUNT][XTCG_HIST_BUCKETS];

static const char * const stat_names[XS__COUNT] = {
    [XS_TB_GEN] = "tb_gen",
    [XS_TB_FLUSH] = "tb_flush",
    [XS_TB_PHYS_INVALIDATE] = "tb_phys_invalidate",
    [XS_TB_EXEC] = "tb_exec",
    [XS_EXIT_REQUESTED] = "exit_requested",
    [XS_EXIT_NOCHAIN] = "exit_nochain",
    [XS_EXIT_NOTB] = "exit_notb",
    [XS_TB_ADD_JUMP] = "tb_add_jump",
    [XS_LOOP_LOOKUP] = "loop_lookup",
    [XS_LOOP_JC_HIT] = "loop_jc_hit",
    [XS_LOOP_HT_HIT] = "loop_ht_hit",
    [XS_LOOKUP_PTR] = "lookup_ptr",
    [XS_LOOKUP_PTR_JC_HIT] = "lookup_ptr_jc_hit",
    [XS_LOOKUP_PTR_HT_HIT] = "lookup_ptr_ht_hit",
    [XS_LOOKUP_PTR_MISS] = "lookup_ptr_miss",
    [XS_EXCEPTION] = "exception",
    [XS_INTERRUPT] = "interrupt",
    [XS_LONGJMP] = "longjmp",
    [XS_TLB_VICTIM_HIT] = "tlb_victim_hit",
    [XS_TLB_FILL] = "tlb_fill",
    [XS_TLB_FLUSH_IDX] = "tlb_flush_idx",
    [XS_TLB_RESIZE] = "tlb_resize",
    [XS_NOTDIRTY_WRITE] = "notdirty_write",
    [XS_NOTDIRTY_CODE] = "notdirty_code",
    [XS_PAGE_UNPROTECT] = "page_unprotect",
    [XS_PAGE_UNPROTECT_DONE] = "page_unprotect_done",
    [XS_PAGE_UNPROTECT_CUR] = "page_unprotect_cur",
    [XS_CC_ALL] = "cc_compute_all",
    [XS_CC_ALL_C] = "cc_compute_all_from_c",
    [XS_CC_C] = "cc_compute_c",
    [XS_CC_NZ] = "cc_compute_nz",
    [XS_JIT_TO_EXEC] = "jit_to_exec",
    [XS_JIT_TO_WRITE] = "jit_to_write",
    [XS_JIT_FLIPS] = "jit_flips",
    [XS_X86_CR3_WRITE] = "x86_cr3_write",
    [XS_X86_CR3_SAME] = "x86_cr3_same",
    [XS_X86_CR3_NOFLUSH] = "x86_cr3_noflush",
    [XS_X86_CR0_FLUSH] = "x86_cr0_flush",
    [XS_X86_CR4_FLUSH] = "x86_cr4_flush",
    [XS_X86_INVLPG] = "x86_invlpg",
    [XS_X86_FILL_GLOBAL] = "x86_fill_global",
    [XS_X86_PCIDE_SET] = "x86_pcide_set",
    [XS_JC_FILL] = "jc_fill",
    [XS_JC_FILL_GLOBAL] = "jc_fill_global",
    [XS_JC_FLUSH_NONGLOBAL] = "jc_flush_nonglobal",
    [XS_JC_CLEAR_PAGE_HIT] = "jc_clear_page_hit",
    [XS_JC_CLEAR_PAGE_KEPT] = "jc_clear_page_kept",
};

static const char * const hist_names[XH__COUNT] = {
    [XH_CC_ALL_OP] = "cc_compute_all.op",
    [XH_CC_C_OP] = "cc_compute_c.op",
    [XH_CC_NZ_OP] = "cc_compute_nz.op",
    [XH_EXCP] = "exception_index",
    [XH_TLB_FILL_BITS] = "tlb_fill.size_bits",
    [XH_TLB_FILL_MMUIDX] = "tlb_fill.mmu_idx",
    [XH_X86_IRQ_LO] = "x86_irq.vector",
    [XH_X86_IRQ_HI] = "x86_irq.vector_minus_128",
    [XH_X86_CR3_PCID] = "x86_cr3.pcid",
    [XH_X86_INVPCID] = "x86_invpcid.type",
};

static bool dumped;

void xtcg_stats_dump(void)
{
    if (!xtcg_stats || qatomic_xchg(&dumped, true)) {
        return;
    }
    for (int i = 0; i < XS__COUNT; i++) {
        fprintf(stderr, "XTCG-STATS %s %" PRIu64 "\n",
                stat_names[i], qatomic_read(&xtcg_stat[i]));
    }
    for (int h = 0; h < XH__COUNT; h++) {
        for (int i = 0; i < XTCG_HIST_BUCKETS; i++) {
            uint64_t v = qatomic_read(&xtcg_hist[h][i]);
            if (v) {
                fprintf(stderr, "XTCG-STATS %s[%d] %" PRIu64 "\n",
                        hist_names[h], i, v);
            }
        }
    }
    fflush(stderr);
}

void xtcg_stats_enable(bool enable)
{
    static bool registered;

    xtcg_stats = enable;
    if (enable && !registered) {
        /*
         * System mode exits normally. linux-user also calls the dump
         * from preexit_cleanup, since exit_group uses _exit.
         */
        atexit(xtcg_stats_dump);
        registered = true;
    }
}

/* Per-thread MAP_JIT mode as last requested: 0 unknown, 1 exec, 2 write. */
static __thread int jit_mode;

void xtcg_stats_jit(bool execute)
{
    int m = execute ? 1 : 2;

    qatomic_inc(&xtcg_stat[execute ? XS_JIT_TO_EXEC : XS_JIT_TO_WRITE]);
    if (jit_mode != m) {
        qatomic_inc(&xtcg_stat[XS_JIT_FLIPS]);
        jit_mode = m;
    }
}
