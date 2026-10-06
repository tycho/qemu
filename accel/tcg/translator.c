/*
 * Generic intermediate code generation.
 *
 * Copyright (C) 2016-2017 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "accel/tcg/cpu-mmu-index.h"
#include "exec/target_page.h"
#include "exec/translator.h"
#include "tcg/startup.h"
#include "exec/icount.h"
#ifdef CONFIG_USER_ONLY
#include "gdbstub/user.h"
#endif
#include "exec/plugin-gen.h"
#include "tcg/tcg-op-common.h"
#include "exec/helper-gen-common.h"
#include "internal-common.h"
#include "disas/disas.h"
#include "tb-internal.h"
#include "tb-hash.h"
#include "tcg/tcg-temp-internal.h"

#ifndef CONFIG_USER_ONLY
static void set_can_do_io(DisasContextBase *db, bool val)
{
    QEMU_BUILD_BUG_ON(sizeof_field(CPUState, neg.can_do_io) != 1);
    tcg_gen_st8_i32(tcg_constant_i32(val), tcg_env,
                    offsetof(CPUState, neg.can_do_io) - sizeof(CPUState));
}
#endif

bool translator_io_start(DisasContextBase *db)
{
    /*
     * Ensure that this instruction will be the last in the TB.
     * The target may override this to something more forceful.
     */
    if (db->is_jmp == DISAS_NEXT) {
        db->is_jmp = DISAS_TOO_MANY;
    }
    return true;
}

static TCGOp *gen_tb_start(DisasContextBase *db, uint32_t cflags)
{
    TCGv_i32 count = NULL;
    TCGOp *icount_start_insn = NULL;

    if ((cflags & CF_USE_ICOUNT) || !(cflags & CF_NOIRQ)) {
        count = tcg_temp_new_i32();
        tcg_gen_ld_i32(count, tcg_env,
                       offsetof(CPUState, neg.icount_decr.u32) -
                       sizeof(CPUState));
    }

    if (cflags & CF_USE_ICOUNT) {
        /*
         * We emit a sub with a dummy immediate argument. Keep the insn index
         * of the sub so that we later (when we know the actual insn count)
         * can update the argument with the actual insn count.
         */
        tcg_gen_sub_i32(count, count, tcg_constant_i32(0));
        icount_start_insn = tcg_last_op();
    }

    /*
     * Emit the check against icount_decr.u32 to see if we should exit
     * unless we suppress the check with CF_NOIRQ. If we are using
     * icount and have suppressed interruption the higher level code
     * should have ensured we don't run more instructions than the
     * budget.
     */
    if (cflags & CF_NOIRQ) {
        tcg_ctx->exitreq_label = NULL;
    } else {
        tcg_ctx->exitreq_label = gen_new_label();
        tcg_gen_brcondi_i32(TCG_COND_LT, count, 0, tcg_ctx->exitreq_label);
    }

    if (cflags & CF_USE_ICOUNT) {
        tcg_gen_st16_i32(count, tcg_env,
                         offsetof(CPUState, neg.icount_decr.u16.low) -
                         sizeof(CPUState));
    }

    return icount_start_insn;
}

static void gen_tb_end(const TranslationBlock *tb, uint32_t cflags,
                       TCGOp *icount_start_insn, int num_insns)
{
    if (cflags & CF_USE_ICOUNT) {
        /*
         * Update the num_insn immediate parameter now that we know
         * the actual insn count.
         */
        tcg_set_insn_param(icount_start_insn, 2,
                           tcgv_i32_arg(tcg_constant_i32(num_insns)));
    }

    if (tcg_ctx->exitreq_label) {
        gen_set_label(tcg_ctx->exitreq_label);
        tcg_gen_exit_tb(tb, TB_EXIT_REQUESTED);
    }
}

void translator_exit_check(DisasContextBase *db, TCGLabel *exit)
{
    TCGv_i32 count = tcg_temp_new_i32();

    tcg_gen_ld_i32(count, tcg_env,
                   offsetof(CPUState, neg.icount_decr.u32) - sizeof(CPUState));
    tcg_gen_brcondi_i32(TCG_COND_LT, count, 0, exit);
    db->tb->loops = true;
}

bool translator_loop_back(DisasContextBase *db, vaddr dest)
{
    TCGLabel *exit;

    if (!db->loop_label || db->region || dest != db->pc_first) {
        return false;
    }
    /*
     * The exit path has a label of its own, reached only from here, so the
     * register allocator can store guest state on that path alone.
     */
    exit = gen_new_label();
    translator_exit_check(db, exit);
    tcg_gen_br(db->loop_label);
    gen_set_label(exit);
    tcg_gen_exit_tb(db->tb, TB_EXIT_REQUESTED);
    return true;
}

/*
 * x-region-hot: multi-block regions.  A backward jump between TBs counts
 * its executions (translator_region_count); past the threshold its
 * destination is promoted: its TB is invalidated and retranslated as a
 * region, one TB that translates the blocks reachable from the head by
 * direct jumps, at or after the head on the head's page and the next one,
 * up to REGION_MAX_BLOCKS blocks and the TB's insn limit.  Jumps between
 * the region's blocks are branches to labels (backward ones check the
 * exit request); other jumps leave the TB.
 */
#define REGION_MAX_BLOCKS 64
#define REGION_COUNTS 4096

static GMutex region_lock;              /* static: needs no init */
static GHashTable *region_heads;        /* promoted heads, under region_lock */
static GHashTable *region_rejected;     /* dropped heads, under region_lock */

/*
 * Debug statistics (XTCG_REGION_STATS=<file>): per region TB, its size
 * and, counted by its code, its entries and internal backward branches.
 * Written at exit.
 */
typedef struct RegionStats {
    uint64_t pc;
    int blocks, insns, backedges, unchained;
    int host_size;
    uint64_t entries, backs;
} RegionStats;

static GPtrArray *region_stats;         /* under region_lock */
static __thread bool region_reject;     /* the region was dropped: retry */
static __thread vaddr region_head_pc;   /* head of the region last tried */
static void region_drop(vaddr pc);
static __thread RegionStats *region_cur_stats;

/*
 * Debug policies (XTCG_REGION_POLICY, comma-separated):
 *   keepflat  keep a region with no branch back to one of its blocks
 *             (by default it is dropped)
 */
static bool region_policy(const char *name)
{
    const char *p = getenv("XTCG_REGION_POLICY");

    return p && strstr(p, name);
}

static void region_stats_dump(void)
{
    const char *path = getenv("XTCG_REGION_STATS");
    FILE *f = fopen(path, "w");
    uint64_t insns = 0, host = 0, entries = 0, backs = 0;
    int few = 0, flat = 0;

    if (!f) {
        return;
    }
    for (guint i = 0; i < region_stats->len; i++) {
        RegionStats *rs = g_ptr_array_index(region_stats, i);

        insns += rs->insns;
        host += rs->host_size;
        entries += rs->entries;
        backs += rs->backs;
        few += rs->entries + rs->backs < 1000;
        flat += rs->backs < rs->entries;
    }
    fprintf(f, "# regions %u guest_insns %" PRIu64 " host_bytes %" PRIu64
            " entries %" PRIu64 " backs %" PRIu64
            " runs<1000 %d backs<entries %d\n",
            region_stats->len, insns, host, entries, backs, few, flat);
    fprintf(f, "# pc blocks insns host backedges unchained entries backs\n");
    for (guint i = 0; i < region_stats->len; i++) {
        RegionStats *rs = g_ptr_array_index(region_stats, i);

        fprintf(f, "%" PRIx64 " %d %d %d %d %d %" PRIu64 " %" PRIu64 "\n",
                rs->pc, rs->blocks, rs->insns, rs->host_size, rs->backedges,
                rs->unchained, rs->entries, rs->backs);
    }
    fclose(f);
}

void translator_region_stats_exit(void)
{
    if (region_stats) {
        region_stats_dump();
    }
}

static void region_count_u64(uint64_t *counter)
{
    TCGv_ptr p = tcg_constant_ptr(counter);
    TCGv_i64 c = tcg_temp_new_i64();

    tcg_gen_ld_i64(c, p, 0);
    tcg_gen_addi_i64(c, c, 1);
    tcg_gen_st_i64(c, p, 0);
}

typedef struct TranslatorRegion {
    CPUState *cpu;
    int backedges;              /* branches back to a block of the region */
    int unchained;              /* direct exits without a goto_tb slot */
    int n;                      /* blocks so far */
    int next;                   /* the next block to translate */
    bool stubbing;              /* insn budget spent: blocks just exit */
    int block_insns;            /* num_insns when the current block began */
    vaddr end;                  /* the end of the highest block */
    vaddr pc[REGION_MAX_BLOCKS];
    TCGLabel *label[REGION_MAX_BLOCKS];
} TranslatorRegion;

static int32_t region_counts[REGION_COUNTS];
static __thread int region_cap;         /* block limit after an overflow */
static __thread int region_tried;       /* blocks of the region last tried */

bool translator_region_overflow(void)
{
    if (region_cap < 0) {
        /* A plain TB: halve its insns as usual. */
        return false;
    }
    if (region_reject) {
        region_reject = false;
        region_cap = -1;
        return true;
    }
    if (region_tried > 1) {
        region_cap = region_tried / 2;
        return true;
    }
    if (region_tried == 1) {
        /* A region of one block gains nothing: translate a plain TB. */
        region_drop(region_head_pc);
        g_free(region_cur_stats);
        region_cur_stats = NULL;
        region_cap = -1;
        return true;
    }
    return false;
}

void translator_region_reset(int host_size)
{
    if (region_cur_stats) {
        region_cur_stats->host_size = host_size;
        g_mutex_lock(&region_lock);
        if (!region_stats) {
            region_stats = g_ptr_array_new();
        }
        g_ptr_array_add(region_stats, region_cur_stats);
        g_mutex_unlock(&region_lock);
        region_cur_stats = NULL;
    }
    region_cap = 0;
    region_tried = 0;
    region_reject = false;
}

/* Drop @pc as a region head (the retry translates it as a plain TB). */
static void region_drop(vaddr pc)
{
    uint64_t key = pc;
    uint64_t *rkey = g_new(uint64_t, 1);

    *rkey = pc;
    g_mutex_lock(&region_lock);
    g_hash_table_remove(region_heads, &key);
    if (!region_rejected) {
        region_rejected = g_hash_table_new(g_int64_hash, g_int64_equal);
    }
    g_hash_table_add(region_rejected, rkey);
    g_mutex_unlock(&region_lock);
}

static unsigned region_hash(vaddr pc)
{
    return (pc ^ (pc >> 12)) & (REGION_COUNTS - 1);
}

static bool region_is_head(vaddr pc)
{
    uint64_t key = pc;
    bool ret;

    g_mutex_lock(&region_lock);
    ret = region_heads && g_hash_table_contains(region_heads, &key);
    g_mutex_unlock(&region_lock);
    return ret;
}

bool translator_region_is_head(vaddr pc)
{
    return region_is_head(pc);
}

bool translator_region_promote(vaddr pc)
{
    uint64_t *key;
    bool added = false;
    const char *only = getenv("XTCG_REGION_ONLY");

    region_counts[region_hash(pc)] = INT32_MIN;
    if (only && strtoull(only, NULL, 16) != pc) {
        return false;
    }
    if (getenv("XTCG_REGION_FIRST")) {
        static int promoted;

        if (promoted >= atoi(getenv("XTCG_REGION_FIRST"))) {
            return false;
        }
        promoted++;
    }
    g_mutex_lock(&region_lock);
    if (!region_heads) {
        region_heads = g_hash_table_new(g_int64_hash, g_int64_equal);
    }
    if (!g_hash_table_contains(region_heads, &pc)
        && !(region_rejected && g_hash_table_contains(region_rejected, &pc))) {
        key = g_new(uint64_t, 1);
        *key = pc;
        g_hash_table_add(region_heads, key);
        added = true;
    }
    g_mutex_unlock(&region_lock);
    return added;
}

void translator_region_count(DisasContextBase *db, vaddr dest)
{
    TCGv_ptr p;
    TCGv_i32 c;
    TCGLabel *skip;

    if (!tcg_region_hot || !db->region_capable || dest == db->pc_first
        || getenv("XTCG_REGION_NOCOUNT") || translator_region_sampling()) {
        return;
    }
    p = tcg_constant_ptr(&region_counts[region_hash(dest)]);
    c = tcg_temp_new_i32();
    skip = gen_new_label();
    tcg_gen_ld_i32(c, p, 0);
    tcg_gen_addi_i32(c, c, 1);
    tcg_gen_st_i32(c, p, 0);
    if (getenv("XTCG_REGION_NOCHECK")) {
        return;
    }
    tcg_gen_brcondi_i32(TCG_COND_LT, c, tcg_region_hot, skip);
    gen_helper_region_hot(tcg_env, tcg_constant_i64(dest));
    gen_set_label(skip);
}

static bool region_page_ok(const DisasContextBase *db, vaddr pc)
{
    vaddr first = db->pc_first & TARGET_PAGE_MASK;

    return pc >= db->pc_first
           && ((pc & TARGET_PAGE_MASK) == first
               || (pc & TARGET_PAGE_MASK) == first + TARGET_PAGE_SIZE);
}

TCGLabel *translator_region_target(DisasContextBase *db, vaddr dest,
                                   bool *backward)
{
    TranslatorRegion *r = db->region;

    *backward = false;
    if (!r || r->stubbing) {
        return NULL;
    }
    for (int i = 0; i < r->n; i++) {
        if (r->pc[i] == dest) {
            if (i == r->next - 1 && db->num_insns == r->block_insns) {
                /* The current block, still empty: don't spin on it. */
                return NULL;
            }
            /* Already emitted (or being emitted): a cycle may close here. */
            *backward = i < r->next;
            if (*backward) {
                r->backedges++;
                if (region_cur_stats) {
                    region_count_u64(&region_cur_stats->backs);
                }
            }
            return r->label[i];
        }
    }
    if (r->n == (region_cap ? region_cap : REGION_MAX_BLOCKS)
        || !region_page_ok(db, dest)
        || !translator_region_has_run(r->cpu, db->tb, dest)
        || (getenv("XTCG_REGION_MAXB")
            && r->n >= atoi(getenv("XTCG_REGION_MAXB")))) {
        return NULL;
    }
    r->pc[r->n] = dest;
    r->label[r->n] = gen_new_label();
    r->label[r->n]->region = true;
    region_tried = r->n + 1;
    return r->label[r->n++];
}

bool translator_region_backward(DisasContextBase *db, vaddr dest)
{
    TranslatorRegion *r = db->region;

    if (!r || r->stubbing) {
        return false;
    }
    for (int i = 0; i < r->next; i++) {
        if (r->pc[i] == dest) {
            return !(i == r->next - 1 && db->num_insns == r->block_insns);
        }
    }
    return false;
}

int translator_goto_tb_slot(DisasContextBase *db, int want)
{
    if (!db->region) {
        return want;
    }
    if (getenv("XTCG_REGION_NOSLOT")) {
        return -1;
    }
    for (int i = 0; i < TB_JMP_SLOTS; i++) {
        int slot = i < 2 ? want ^ i : i;

        if (slot != TB_EXIT_REQUESTED && !(db->goto_tb_used & (1u << slot))) {
            db->goto_tb_used |= 1u << slot;
            return slot;
        }
    }
    db->region->unchained++;
    return -1;
}

bool translator_in_tb_pages(const DisasContextBase *db, vaddr addr)
{
    return translator_is_same_page(db, addr)
           || (db->region && region_page_ok(db, addr));
}

bool translator_is_same_page(const DisasContextBase *db, vaddr addr)
{
    return ((addr ^ db->pc_first) & TARGET_PAGE_MASK) == 0;
}

/*
 * Whether a direct jump may be chained to a destination outside the page
 * the TB started in.
 *
 * In user-only mode there are no page tables.  Every mmap, mprotect and
 * munmap goes through page_set_flags(), which calls tb_invalidate_phys_range()
 * whenever a change in flags so warrants, and tb_phys_invalidate() unlinks
 * incoming jumps.  A cross-page link is therefore broken whenever the
 * destination page's permissions change.
 *
 * What the same-page rule also provides is that execution cannot enter a page
 * without a TB lookup, and so without check_for_breakpoints(), which is what
 * makes a breakpoint set after a block was translated take effect.  Nothing
 * invalidates on breakpoint insertion, so a link established beforehand would
 * jump straight over it.  In user-only mode breakpoints only ever come from
 * gdb -- BP_CPU is g_assert_not_reached() there and the guest has no way to
 * ask for one -- and gdb has to be requested with -g before the first block
 * is translated, so a run that has no gdbstub can never acquire a breakpoint.
 */
static bool use_cross_page_goto_tb(void)
{
#ifdef CONFIG_USER_ONLY
    return !gdb_may_set_breakpoints();
#else
    return false;
#endif
}

bool translator_use_goto_tb(DisasContextBase *db, vaddr dest)
{
    /* Suppress goto_tb if requested. */
    if (tb_cflags(db->tb) & CF_NO_GOTO_TB) {
        return false;
    }

    /* Check for the dest on the same page as the start of the TB.  */
    return use_cross_page_goto_tb() || translator_is_same_page(db, dest);
}

bool translator_use_inline_lookup(DisasContextBase *db)
{
    return tcg_ijmp_inline &&
           !(tb_cflags(db->tb) & (CF_NO_GOTO_PTR | CF_USE_ICOUNT)) &&
           !qemu_loglevel_mask(CPU_LOG_TB_CPU | CPU_LOG_EXEC);
}

/*
 * Byte offset of @pc's entry in CPUJumpCache.array, computed as
 * tb_jmp_cache_hash_func() does.
 */
static void gen_jmp_cache_offset(TCGv_i64 off, TCGv_i64 pc)
{
#define JC_ENTRY_SIZE sizeof_field(CPUJumpCache, array[0])
    const unsigned e = ctz32(JC_ENTRY_SIZE);
    TCGv_i64 tmp = tcg_temp_ebb_new_i64();

    QEMU_BUILD_BUG_ON(JC_ENTRY_SIZE & (JC_ENTRY_SIZE - 1));
#undef JC_ENTRY_SIZE
#ifdef CONFIG_SOFTMMU
    TCGv_i64 hi = tcg_temp_ebb_new_i64();
    const unsigned sh = TARGET_PAGE_BITS - TB_JMP_PAGE_BITS;

    tcg_gen_shri_i64(tmp, pc, sh);
    tcg_gen_xor_i64(tmp, tmp, pc);
    tcg_gen_shri_i64(hi, tmp, sh + TB_JMP_PAGE_BITS);
    tcg_gen_deposit_z_i64(hi, hi, e + TB_JMP_PAGE_BITS,
                          TB_JMP_CACHE_BITS - TB_JMP_PAGE_BITS);
    tcg_gen_deposit_z_i64(off, tmp, e, TB_JMP_PAGE_BITS);
    tcg_gen_or_i64(off, off, hi);
    tcg_temp_free_i64(hi);
#else
    tcg_gen_shri_i64(tmp, pc, TB_JMP_CACHE_BITS);
    tcg_gen_xor_i64(tmp, tmp, pc);
    tcg_gen_deposit_z_i64(off, tmp, e, TB_JMP_CACHE_BITS);
#endif
    tcg_temp_free_i64(tmp);
}

/*
 * Whether a breakpoint can be inserted while generated code runs, and so
 * whether the inline lookup must defer to the helper, which checks them.
 */
static bool inline_lookup_checks_breakpoints(void)
{
#ifdef CONFIG_USER_ONLY
    return gdb_may_set_breakpoints();
#else
    return true;
#endif
}

static void gen_inline_lookup(TCGv_i64 pc, uint64_t cs_base, uint32_t flags)
{
    TCGLabel *miss = gen_new_label();
    TCGv_ptr jc = tcg_temp_ebb_new_ptr();
    TCGv_ptr tb = tcg_temp_ebb_new_ptr();
    TCGv_i64 t64 = tcg_temp_ebb_new_i64();
    TCGv_i32 t32 = tcg_temp_ebb_new_i32();
    TCGv_i32 cf = tcg_temp_ebb_new_i32();
    TCGv_i64 key = pc;

    plugin_gen_disable_mem_helpers();

    /*
     * The same checks as tb_lookup(), against the jump cache only.  The
     * cache holds only TBs that are valid for the vCPU's current mappings:
     * TLB flushes clear it (or move its salt on), and TB invalidation
     * removes the TB from it.
     * The pc is compared before the first branch, so it needn't stay live
     * across them.
     */
    tcg_gen_ld_ptr(jc, tcg_env,
                   offsetof(CPUState, tb_jmp_cache) - sizeof(CPUState));
    if (tcg_jcgen) {
        /* Entries hold pc ^ salt; a flush moves the salt on. */
        key = tcg_temp_ebb_new_i64();
        tcg_gen_ld_i64(key, jc, offsetof(CPUJumpCache, salt));
        tcg_gen_xor_i64(key, key, pc);
    }
    gen_jmp_cache_offset(t64, pc);
    tcg_gen_trunc_i64_ptr(tb, t64);
    tcg_gen_add_ptr(jc, jc, tb);
    QEMU_BUILD_BUG_ON(sizeof(vaddr) != sizeof(uint64_t));
    tcg_gen_ld_i64(t64, jc, offsetof(CPUJumpCache, array[0].pc));
    tcg_gen_ld_ptr(tb, jc, offsetof(CPUJumpCache, array[0].tb));
    tcg_gen_brcond_i64(TCG_COND_NE, t64, key, miss);
    tcg_gen_brcondi_ptr(TCG_COND_EQ, tb, 0, miss);

    /* check_for_breakpoints() runs only in the helper. */
    if (inline_lookup_checks_breakpoints()) {
        tcg_gen_ld_ptr(jc, tcg_env,
                       offsetof(CPUState, breakpoints.tqh_first) -
                       sizeof(CPUState));
        tcg_gen_brcondi_ptr(TCG_COND_NE, jc, 0, miss);
    }

    tcg_gen_ld_i64(t64, tb, offsetof(TranslationBlock, cs_base));
    tcg_gen_brcondi_i64(TCG_COND_NE, t64, cs_base, miss);
    tcg_gen_ld_i32(t32, tb, offsetof(TranslationBlock, flags));
    tcg_gen_brcondi_i32(TCG_COND_NE, t32, flags, miss);

    /* curr_cflags(); a stale TB has CF_INVALID set and never matches. */
    tcg_gen_ld_i32(t32, tb, offsetof(TranslationBlock, cflags));
    tcg_gen_ld_i32(cf, tcg_env,
                   offsetof(CPUState, tcg_cflags) - sizeof(CPUState));
    tcg_gen_brcond_i32(TCG_COND_NE, t32, cf, miss);

    tcg_gen_ld_ptr(tb, tb, offsetof(TranslationBlock, tc.ptr));
    tcg_gen_goto_ptr(tb);

    gen_set_label(miss);
    tcg_gen_lookup_and_goto_ptr();

    if (key != pc) {
        tcg_temp_free_i64(key);
    }
    tcg_temp_free_i32(cf);
    tcg_temp_free_i32(t32);
    tcg_temp_free_i64(t64);
    tcg_temp_free_ptr(tb);
    tcg_temp_free_ptr(jc);
}

void translator_lookup_and_goto_ptr(DisasContextBase *db, TCGv_i64 pc,
                                    uint64_t cs_base, uint32_t flags,
                                    bool direct)
{
    assert(translator_use_inline_lookup(db));
    if (direct) {
        tcg_gen_lookup_jc_and_goto_ptr(pc, cs_base, flags);
    } else {
        gen_inline_lookup(pc, cs_base, flags);
    }
}

void translator_loop(CPUState *cpu, TranslationBlock *tb, int *max_insns,
                     vaddr pc, void *host_pc, const TranslatorOps *ops,
                     DisasContextBase *db, TCGType addr_type)
{
    uint32_t cflags = tb_cflags(tb);
    TCGOp *icount_start_insn;
    TCGOp *loop_op = NULL;
    bool plugin_enabled;
#ifndef CONFIG_USER_ONLY
    TCGOp *first_insn_start = NULL;
#endif

    tcg_ctx->addr_type = addr_type;

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = pc;
    db->pc_next = pc;
    db->pc_second_page = -1;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->max_insns = *max_insns;
    db->insn_start = NULL;
    db->fake_insn = false;
    db->host_addr[0] = host_pc;
    db->host_addr[1] = NULL;
    db->record_start = 0;
    db->record_len = 0;
    db->code_mmuidx = cpu_mmu_index(cpu, true);

    ops->init_disas_context(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    /* Start translating.  */
    icount_start_insn = gen_tb_start(db, cflags);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    plugin_enabled = plugin_gen_tb_start(cpu, db);
    db->plugin_enabled = plugin_enabled;

    /*
     * With tcg_region, a TB may branch back to its first insn instead
     * of chaining to itself.  Not with icount (the budget is charged per
     * TB entry), plugins (they count TB executions) or without an exit
     * check.
     */
    db->loop_label = NULL;
    db->region = NULL;
    db->goto_tb_used = 0;
    db->region_capable = false;
    if (tcg_region && !plugin_enabled && tcg_ctx->exitreq_label
        && !(cflags & CF_USE_ICOUNT)) {
        db->loop_label = gen_new_label();
        db->loop_label->loop = true;
        gen_set_label(db->loop_label);
        loop_op = tcg_last_op();
        db->region_capable = ops->block_start && tb_page_addr0(tb) != -1;
    }
    if (db->region_capable && tcg_region_hot && region_cap >= 0
        && region_is_head(pc)) {
        TranslatorRegion *r = tcg_malloc(sizeof(*r));

        g_free(region_cur_stats);
        region_cur_stats = NULL;
        if (getenv("XTCG_REGION_STATS")) {
            region_cur_stats = g_new0(RegionStats, 1);
            region_cur_stats->pc = pc;
            /* Count entries before the head's label. */
            tcg_ctx->emit_before_op = loop_op;
            region_count_u64(&region_cur_stats->entries);
            tcg_ctx->emit_before_op = NULL;
        }
        r->cpu = cpu;
        r->backedges = 0;
        region_head_pc = pc;
        r->unchained = 0;
        r->n = r->next = 1;
        region_tried = 1;
        r->stubbing = false;
        r->block_insns = 0;
        r->end = pc;
        r->pc[0] = pc;
        r->label[0] = db->loop_label;
        db->loop_label->loop = false;
        db->loop_label->region = true;
        db->region = r;
    }

 next_block:
    while (!(db->region && db->region->stubbing)) {
        vaddr insn_pc = db->pc_next;

        *max_insns = ++db->num_insns;
        ops->insn_start(db, cpu);
        db->insn_start = tcg_last_op();
#ifndef CONFIG_USER_ONLY
        if (first_insn_start == NULL) {
            first_insn_start = db->insn_start;
        }
#endif
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

        if (plugin_enabled) {
            plugin_gen_insn_start(cpu, db);
        }

        /*
         * Disassemble one instruction.  The translate_insn hook should
         * update db->pc_next and db->is_jmp to indicate what should be
         * done next -- either exiting this loop or locate the start of
         * the next instruction.
         */
        tcg_ctx->insn_pc = db->pc_next;
        tcg_ctx->ldst_private = false;
        tcg_ctx->gen_insn_pc[db->num_insns - 1] = db->pc_next;
        ops->translate_insn(db, cpu);

        /*
         * We can't instrument after instructions that change control
         * flow although this only really affects post-load operations.
         *
         * Calling plugin_gen_insn_end() before we possibly stop translation
         * is important. Even if this ends up as dead code, plugin generation
         * needs to see a matching plugin_gen_insn_{start,end}() pair in order
         * to accurately track instrumented helpers that might access memory.
         */
        if (plugin_enabled) {
            plugin_gen_insn_end();
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /*
         * End the TB after an instruction known to do I/O, so that its
         * accesses happen with can_do_io set.
         */
        if (tcg_iolast && !icount_enabled() &&
            tb_io_insn_known(insn_pc)) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= db->max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            if (db->region) {
                db->region->stubbing = true;
            }
            break;
        }
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    if (db->region) {
        TranslatorRegion *r = db->region;

        r->end = MAX(r->end, db->pc_next);
        if (r->next < r->n) {
            /*
             * The next block of the region.  Once the insn budget is spent,
             * the remaining blocks only jump out to themselves.
             */
            gen_set_label(r->label[r->next]);
            db->pc_next = r->pc[r->next++];
            db->is_jmp = r->stubbing ? DISAS_TOO_MANY : DISAS_NEXT;
            r->block_insns = db->num_insns;
            ops->block_start(db, cpu);
            if (tcg_op_buf_full() || db->num_insns >= db->max_insns) {
                r->stubbing = true;
                db->is_jmp = DISAS_TOO_MANY;
            }
            goto next_block;
        }
        db->pc_next = r->end;
        if (region_cur_stats) {
            region_cur_stats->blocks = r->n;
            region_cur_stats->insns = db->num_insns;
            region_cur_stats->backedges = r->backedges;
            region_cur_stats->unchained = r->unchained;
        }
        if (r->n == 1 || (!region_policy("keepflat") && !r->backedges)) {
            /*
             * One block (a plain TB loops on itself already), or nothing
             * loops inside: translate the head as a plain TB.
             */
            region_drop(db->pc_first);
            region_reject = true;
            g_free(region_cur_stats);
            region_cur_stats = NULL;
            siglongjmp(tcg_ctx->jmp_trans, -2);
        }
        if (getenv("XTCG_REGION_DEBUG")) {
            fprintf(stderr, "region %" PRIx64 ": %d blocks, %d insns, "
                    "slots %x, %d unchained%s\n",
                    (uint64_t)db->pc_first, r->n, db->num_insns,
                    db->goto_tb_used, r->unchained,
                    r->stubbing ? ", stubbed" : "");
        }
    }
    gen_tb_end(tb, cflags, icount_start_insn, db->num_insns);

#ifndef CONFIG_USER_ONLY
    /*
     * Manage can_do_io for the translation block: set to false before
     * the first insn and set to true before the last insn.
     *
     * Nothing reads can_do_io in user-only builds.  There is no MMIO
     * there, and every reader (cputlb.c, watchpoint.c, icount) is in
     * system_ss, so skip the two stores per TB entirely.
     */
    if (db->num_insns == 1) {
        tcg_debug_assert(first_insn_start == db->insn_start);
    } else {
        tcg_debug_assert(first_insn_start != db->insn_start);
        tcg_ctx->emit_before_op = first_insn_start;
        set_can_do_io(db, false);
    }
    tcg_ctx->emit_before_op = db->insn_start;
    set_can_do_io(db, true);
    tcg_ctx->emit_before_op = NULL;
#endif

    /* May be used by disas_log or plugin callbacks. */
    tb->size = db->pc_next - db->pc_first;
    tb->icount = db->num_insns;

    if (plugin_enabled) {
        plugin_gen_tb_end(cpu, db->num_insns);
    }

    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            fprintf(logfile, "----------------\n");

            if (!ops->disas_log ||
                !ops->disas_log(db, cpu, logfile)) {
                fprintf(logfile, "IN: %s\n", lookup_symbol(db->pc_first));
                target_disas(logfile, cpu, db);
            }
            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }
}

static bool translator_ld(CPUArchState *env, DisasContextBase *db,
                          void *dest, vaddr pc, size_t len)
{
    TranslationBlock *tb = db->tb;
    vaddr last = pc + len - 1;
    void *host;
    vaddr base;

    /* Use slow path if first page is MMIO. */
    if (unlikely(tb_page_addr0(tb) == -1)) {
        /* We capped translation with first page MMIO in tb_gen_code. */
        tcg_debug_assert(db->max_insns == 1);
        return false;
    }

    host = db->host_addr[0];
    base = db->pc_first;

    if (likely(((base ^ last) & TARGET_PAGE_MASK) == 0)) {
        /* Entire read is from the first page. */
        goto do_read;
    }

    if (unlikely(((base ^ pc) & TARGET_PAGE_MASK) == 0)) {
        /*
         * Read begins on the first page and extends to the second.
         * The unaligned read is never atomic.
         */
        size_t len0 = -(pc | TARGET_PAGE_MASK);
        memcpy(dest, host + (pc - base), len0);
        pc += len0;
        dest += len0;
        len -= len0;
    }

    /*
     * The read must conclude on the second page and not extend to a third.
     *
     * TODO: This doesn't handle address space wraparound properly for
     * multi-byte reads, as we don't know the size of the address space here.
     * But if the target translator wraps pc to 0 itself, and issues aligned
     * reads, then this can work.
     */
    if (db->pc_second_page == -1) {
        db->pc_second_page = pc & TARGET_PAGE_MASK;
    } else {
        assert((pc & TARGET_PAGE_MASK) == db->pc_second_page);
    }
    assert((last & TARGET_PAGE_MASK) == db->pc_second_page);
    base = db->pc_second_page;
    host = db->host_addr[1];

    if (host == NULL) {
        tb_page_addr_t page0, old_page1, new_page1;

        new_page1 = get_page_addr_code_hostp(env, base, &db->host_addr[1]);

        /*
         * If the second page is MMIO, treat as if the first page
         * was MMIO as well, so that we do not cache the TB.
         */
        if (unlikely(new_page1 == -1)) {
            tb_unlock_pages(tb);
            tb_set_page_addr0(tb, -1);
            /* Require that this be the final insn. */
            db->max_insns = db->num_insns;
            return false;
        }

        /*
         * If this is not the first time around, and page1 matches,
         * then we already have the page locked.  Alternately, we're
         * not doing anything to prevent the PTE from changing, so
         * we might wind up with a different page, requiring us to
         * re-do the locking.
         */
        old_page1 = tb_page_addr1(tb);
        if (likely(new_page1 != old_page1)) {
            page0 = tb_page_addr0(tb);
            if (unlikely(old_page1 != -1)) {
                tb_unlock_page1(page0, old_page1);
            }
            tb_set_page_addr1(tb, new_page1);
            tb_lock_page1(page0, new_page1);
        }
        host = db->host_addr[1];
    }

 do_read:
    /*
     * Assume aligned reads should be atomic, if possible.
     * We're not in a position to jump out with EXCP_ATOMIC.
     */
    host += pc - base;
    switch (len) {
    case 2:
        if (QEMU_IS_ALIGNED(pc, 2)) {
            uint16_t t = qatomic_read((uint16_t *)host);
            stw_he_p(dest, t);
            return true;
        }
        break;
    case 4:
        if (QEMU_IS_ALIGNED(pc, 4)) {
            uint32_t t = qatomic_read((uint32_t *)host);
            stl_he_p(dest, t);
            return true;
        }
        break;
    case 8:
        if (QEMU_IS_ALIGNED(pc, 8)) {
            uint64_t t = qatomic_read((uint64_t *)host);
            stq_he_p(dest, t);
            return true;
        }
        break;
    }
    /* Unaligned or partial read from the second page is not atomic. */
    memcpy(dest, host, len);
    return true;
}

static void record_save(DisasContextBase *db, vaddr pc,
                        const void *from, int size)
{
    int offset;

    /*
     * In translator_ld, we verified that we touched no more than 2 pages,
     * but we did not verify that they were virtually contiguous.
     * Here, reimagine the two pages as virtually contiguous.
     */
    if (likely(((db->pc_first ^ pc) & TARGET_PAGE_MASK) == 0)) {
        /* first page */
        /* Do not record probes before the start of TB. */
        if (pc < db->pc_first) {
            return;
        }
        offset = pc - db->pc_first;
    } else {
        int first_page_end_offset = -(db->pc_first | TARGET_PAGE_MASK);
        assert(db->pc_second_page != -1);
        assert((pc & TARGET_PAGE_MASK) == db->pc_second_page);
        offset = pc - db->pc_second_page + first_page_end_offset;
    }

    /*
     * Either the first or second page may be I/O.  If it is the second,
     * then the first byte we need to record will be at a non-zero offset.
     * In either case, we should not need to record but a single insn.
     *
     * A read may re-read bytes that are already recorded: a target may
     * fetch a whole aligned word to decode an insn (e.g. riscv Ziccif),
     * then probe the following insn, which lies within that same word.
     * Such a read extends the record only by the bytes past its end.
     */
    if (db->record_len == 0) {
        db->record_start = offset;
        db->record_len = size;
    } else {
        int end = offset - db->record_start + size;

        assert(offset >= db->record_start);
        assert(offset <= db->record_start + db->record_len);
        assert(end <= sizeof(db->record));
        db->record_len = MAX(db->record_len, end);
    }

    memcpy(db->record + (offset - db->record_start), from, size);
}

size_t translator_st_len(const DisasContextBase *db)
{
    return db->fake_insn ? db->record_len : db->tb->size;
}

bool translator_st(const DisasContextBase *db, void *dest,
                   vaddr addr, size_t len)
{
    size_t offset, offset_end;

    if (addr < db->pc_first) {
        return false;
    }
    offset = addr - db->pc_first;
    offset_end = offset + len;
    if (offset_end > translator_st_len(db)) {
        return false;
    }

    if (!db->fake_insn) {
        size_t offset_page1 = -(db->pc_first | TARGET_PAGE_MASK);

        /* Get all the bytes from the first page. */
        if (db->host_addr[0]) {
            if (offset_end <= offset_page1) {
                memcpy(dest, db->host_addr[0] + offset, len);
                return true;
            }
            if (offset < offset_page1) {
                size_t len0 = offset_page1 - offset;
                memcpy(dest, db->host_addr[0] + offset, len0);
                offset += len0;
                dest += len0;
            }
        }

        /* Get any bytes from the second page. */
        if (db->host_addr[1] && offset >= offset_page1) {
            memcpy(dest, db->host_addr[1] + (offset - offset_page1),
                   offset_end - offset);
            return true;
        }
    }

    /* Else get recorded bytes. */
    if (db->record_len != 0 &&
        offset >= db->record_start &&
        offset_end <= db->record_start + db->record_len) {
        memcpy(dest, db->record + (offset - db->record_start),
               offset_end - offset);
        return true;
    }
    return false;
}

uint8_t translator_ldub(CPUArchState *env, DisasContextBase *db, vaddr pc)
{
    uint8_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UB, db->code_mmuidx);
        val = cpu_ldb_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    return val;
}

uint16_t translator_lduw_end(CPUArchState *env, DisasContextBase *db,
                             vaddr pc, MemOp endian)
{
    uint16_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UW, db->code_mmuidx);
        val = cpu_ldw_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    if (endian & MO_BSWAP) {
        val = bswap16(val);
    }
    return val;
}

uint32_t translator_ldl_end(CPUArchState *env, DisasContextBase *db,
                            vaddr pc, MemOp endian)
{
    uint32_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UL, db->code_mmuidx);
        val = cpu_ldl_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    if (endian & MO_BSWAP) {
        val = bswap32(val);
    }
    return val;
}

uint64_t translator_ldq_end(CPUArchState *env, DisasContextBase *db,
                            vaddr pc, MemOp endian)
{
    uint64_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UQ, db->code_mmuidx);
        val = cpu_ldq_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    if (endian & MO_BSWAP) {
        val = bswap64(val);
    }
    return val;
}

void translator_fake_ld(DisasContextBase *db, const void *data, size_t len)
{
    db->fake_insn = true;
    record_save(db, db->pc_first, data, len);
}
