/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * xtcg Phase-1 event counters (development aid, not for upstream).
 *
 * Enabled with -accel tcg,x-stats=on (system) or QEMU_XTCG=stats
 * (linux-user). When disabled, each counting site costs one load and a
 * not-taken branch; generated code is unchanged either way. The counts
 * are printed to stderr at exit, one "XTCG-STATS <name> <value>" line
 * each.
 */

#ifndef QEMU_XTCG_STATS_H
#define QEMU_XTCG_STATS_H

#include "qemu/atomic.h"

typedef enum XtcgStat {
    /* translation and the TB cache */
    XS_TB_GEN,              /* tb_gen_code calls */
    XS_TB_FLUSH,            /* full flushes */
    XS_TB_PHYS_INVALIDATE,  /* single TBs invalidated */
    /* main loop and chaining */
    XS_TB_EXEC,             /* entries into generated code (cpu_tb_exec) */
    XS_EXIT_REQUESTED,      /* ... that returned TB_EXIT_REQUESTED */
    XS_EXIT_NOCHAIN,        /* ... that returned via an unpatched goto_tb */
    XS_EXIT_NOTB,           /* ... that returned without a last TB */
    XS_TB_ADD_JUMP,         /* chain patch attempts */
    XS_LOOP_LOOKUP,         /* main-loop tb_lookup calls */
    XS_LOOP_JC_HIT,         /* ... hit in tb_jmp_cache */
    XS_LOOP_HT_HIT,         /* ... hit in the qht */
    /* helper_lookup_tb_ptr (indirect branches, CH-05) */
    XS_LOOKUP_PTR,          /* calls */
    XS_LOOKUP_PTR_JC_HIT,   /* ... hit in tb_jmp_cache */
    XS_LOOKUP_PTR_HT_HIT,   /* ... hit in the qht */
    XS_LOOKUP_PTR_MISS,     /* ... returned to the epilogue */
    /* exceptions and interrupts */
    XS_EXCEPTION,           /* guest exceptions (index < EXCP_INTERRUPT) */
    XS_INTERRUPT,           /* cpu_handle_interrupt that took an interrupt */
    XS_LONGJMP,             /* returns to cpu_exec via siglongjmp */
    /* softmmu TLB and SMC (system mode, CH-06) */
    XS_TLB_VICTIM_HIT,
    XS_TLB_FILL,            /* tlb_fill_align calls (page walks) */
    XS_NOTDIRTY_WRITE,      /* stores taking the TLB_NOTDIRTY slow path */
    XS_NOTDIRTY_CODE,       /* ... whose range still held code */
    /* user-mode SMC (CH-06) */
    XS_PAGE_UNPROTECT,      /* page_unprotect calls */
    XS_PAGE_UNPROTECT_DONE, /* ... that made a page writable */
    XS_PAGE_UNPROTECT_CUR,  /* ... that invalidated the current TB */
    /* x86 lazy flags (CH-04) */
    XS_CC_ALL,              /* helper_cc_compute_all, incl. from C */
    XS_CC_ALL_C,            /* cpu_cc_compute_all (C callers only) */
    XS_CC_C,                /* helper_cc_compute_c */
    XS_CC_NZ,               /* helper_cc_compute_nz */
    /* macOS MAP_JIT W^X toggles (CH-09) */
    XS_JIT_TO_EXEC,         /* qemu_thread_jit_execute calls */
    XS_JIT_TO_WRITE,        /* qemu_thread_jit_write calls */
    XS_JIT_FLIPS,           /* ... that changed this thread's mode */
    XS__COUNT
} XtcgStat;

/* Histograms, indexed by a small integer (e.g. the incoming cc_op). */
typedef enum XtcgHist {
    XH_CC_ALL_OP,
    XH_CC_C_OP,
    XH_CC_NZ_OP,
    XH_EXCP,                /* exception_index, see xtcg_excp_bucket() */
    XH__COUNT
} XtcgHist;

#define XTCG_HIST_BUCKETS 128

extern bool xtcg_stats;
extern uint64_t xtcg_stat[XS__COUNT];
extern uint64_t xtcg_hist[XH__COUNT][XTCG_HIST_BUCKETS];

void xtcg_stats_enable(bool enable);
void xtcg_stats_dump(void);
void xtcg_stats_jit(bool execute);

static inline void xtcg_stat_inc(XtcgStat s)
{
    if (unlikely(xtcg_stats)) {
        qatomic_inc(&xtcg_stat[s]);
    }
}

static inline void xtcg_hist_inc(XtcgHist h, unsigned idx)
{
    if (unlikely(xtcg_stats)) {
        qatomic_inc(&xtcg_hist[h][MIN(idx, XTCG_HIST_BUCKETS - 1)]);
    }
}

/*
 * Histogram bucket for an exception_index: guest vectors 0-63 as they are;
 * target-private codes from 0x100 (e.g. x86 EXCP_SYSCALL, 0x101) at
 * 64 + (index - 0x100); QEMU's EXCP_INTERRUPT (0x10000) and up at
 * 112 + (index - 0x10000). Out-of-range values saturate.
 */
static inline unsigned xtcg_excp_bucket(int index)
{
    if (index >= 0x10000) {
        return 112 + MIN(index - 0x10000, 15);
    }
    if (index >= 0x100) {
        return 64 + MIN(index - 0x100, 47);
    }
    return MIN(index, 63);
}

#endif
