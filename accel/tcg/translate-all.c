/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "tcg/tcg-cache.h"
#include "qemu/timer.h"
#include "qemu/cacheflush.h"
#ifdef CONFIG_USER_ONLY
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "exec/page-protection.h"
#endif

#include "trace.h"
#include "disas/disas.h"
#include "tcg/tcg.h"
#include "tcg/startup.h"
#include "exec/mmap-lock.h"
#include "tb-internal.h"
#include "exec/tb-flush.h"
#include "qemu/target-info.h"
#include "exec/log.h"
#include "exec/icount.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/cpu-ops.h"
#include "accel/tcg/host-fp.h"
#include "tb-jmp-cache.h"
#include "tb-hash.h"
#include "tb-context.h"
#include "internal-common.h"
#include "tcg/perf.h"
#include "qemu/plugin.h"
#include "tcg/insn-start-words.h"
#ifdef CONFIG_USER_ONLY
#include "user/cpu_loop.h"
#endif

TBContext tb_ctx;

/*
 * Encode VAL as a signed leb128 sequence at P.
 * Return P incremented past the encoded value.
 */
static uint8_t *encode_sleb128(uint8_t *p, int64_t val)
{
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0)
                 || (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

/*
 * Decode a signed leb128 sequence at *PP; increment *PP past the
 * decoded value.  Return the decoded value.
 */
static int64_t decode_sleb128(const uint8_t **pp)
{
    const uint8_t *p = *pp;
    int64_t val = 0;
    int byte, shift = 0;

    do {
        byte = *p++;
        val |= (int64_t)(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) {
        val |= -(int64_t)1 << shift;
    }

    *pp = p;
    return val;
}

/* Encode the data collected about the instructions while compiling TB.
   Place the data at BLOCK, and return the number of bytes consumed.

   The logical table consists of INSN_START_WORDS uint64_t's,
   which come from the target's insn_start data, followed by a uintptr_t
   which comes from the host pc of the end of the code implementing the insn.

   Each line of the table is encoded as sleb128 deltas from the previous
   line.  The seed for the first line is { tb->pc, 0..., tb->tc.ptr }.
   That is, the first column is seeded with the guest pc, the last column
   with the host pc, and the middle columns with zeros.  */

/* tcg_lazysync map: the register byte of a constant-valued global. */
#define LAZY_WB_CONST TCG_CACHE_LAZY_WB_CONST

static int encode_search(TranslationBlock *tb, uint8_t *block,
                         uint8_t *highwater)
{
    uint64_t *insn_data = tcg_ctx->gen_insn_data;
    uint16_t *insn_end_off = tcg_ctx->gen_insn_end_off;
    uint8_t *p = block;
    int i, j, n;

    for (i = 0, n = tb->icount; i < n; ++i) {
        uint64_t prev, curr;

        for (j = 0; j < INSN_START_WORDS; ++j) {
            if (i == 0) {
                prev = (!(tb_cflags(tb) & CF_PCREL) && j == 0 ? tb->pc : 0);
            } else {
                prev = insn_data[(i - 1) * INSN_START_WORDS + j];
            }
            curr = insn_data[i * INSN_START_WORDS + j];
            p = encode_sleb128(p, curr - prev);
        }
        prev = (i == 0 ? 0 : insn_end_off[i - 1]);
        curr = insn_end_off[i];
        p = encode_sleb128(p, curr - prev);

        /* Test for (pending) buffer overflow.  The assumption is that any
           one row beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           encoding a row without having to check during encoding.  */
        if (unlikely(p > highwater)) {
            return -1;
        }
    }

#ifdef CONFIG_USER_ONLY
    /* tcg_lazysync: the dirty globals per guest access, after the rows. */
    if (tcg_lazysync_user) {
        TCGContext *s = tcg_ctx;

        p = encode_sleb128(p, s->nb_lazy_map);
        for (i = 0; i < s->nb_lazy_map; ++i) {
            const TCGLazyMap *m = &s->lazy_map[i];

            p = encode_sleb128(p, m->start);
            p = encode_sleb128(p, m->end - m->start);
            p = encode_sleb128(p, m->nb_wb);
            for (j = 0; j < m->nb_wb; ++j) {
                *p++ = m->wb[j].is_const ? LAZY_WB_CONST : m->wb[j].reg;
                *p++ = m->wb[j].base;
                *p++ = m->wb[j].type;
                p = encode_sleb128(p, m->wb[j].offset);
                if (m->wb[j].is_const) {
                    p = encode_sleb128(p, m->wb[j].val);
                }
            }
            if (unlikely(p > highwater)) {
                return -1;
            }
        }
    }
#endif

    return p - block;
}

#ifdef CONFIG_USER_ONLY
/*
 * A host signal at @host_pc in generated code: if it is a guest access
 * that left dirty globals in registers (tcg_lazysync), store them from
 * @regs, the host's registers at the signal, numbered as TCGReg.
 */
void tb_lazysync_unwind(uintptr_t host_pc, const uint64_t (*regs)[2],
                        int nregs)
{
    TranslationBlock *tb;
    const uint8_t *p;
    uintptr_t off;
    int n;

    if (!tcg_lazysync_user) {
        return;
    }
    tb = tcg_tb_lookup(host_pc);
    if (!tb || host_pc < (uintptr_t)tb->tc.ptr) {
        return;
    }
    off = host_pc - (uintptr_t)tb->tc.ptr;
    p = tb->tc.search;
    for (int i = 0; i < tb->icount * (INSN_START_WORDS + 1); ++i) {
        decode_sleb128(&p);
    }
    n = decode_sleb128(&p);
    for (int i = 0; i < n; ++i) {
        uintptr_t start = decode_sleb128(&p);
        uintptr_t len = decode_sleb128(&p);
        int nb_wb = decode_sleb128(&p);
        bool hit = off >= start && off < start + len;

        for (int j = 0; j < nb_wb; ++j) {
            unsigned reg = *p++;
            TCGReg base = *p++;
            TCGType type = *p++;
            intptr_t ofs = decode_sleb128(&p);
            uint64_t val = reg == LAZY_WB_CONST ? decode_sleb128(&p) : 0;

            if (hit && base < nregs && (reg == LAZY_WB_CONST || reg < nregs)) {
                uint64_t *dst = (void *)(uintptr_t)(regs[base][0] + ofs);

                if (reg == LAZY_WB_CONST) {
                    if (type == TCG_TYPE_I32) {
                        *(uint32_t *)dst = val;
                    } else {
                        dst[0] = val;
                    }
                    continue;
                }
                switch (type) {
                case TCG_TYPE_I32:
                    *(uint32_t *)dst = regs[reg][0];
                    break;
                case TCG_TYPE_I64:
                case TCG_TYPE_V64:
                    dst[0] = regs[reg][0];
                    break;
                case TCG_TYPE_V128:
                    dst[0] = regs[reg][0];
                    dst[1] = regs[reg][1];
                    break;
                default:
                    g_assert_not_reached();
                }
            }
        }
        if (hit) {
            return;
        }
    }
}
#endif

static int cpu_unwind_data_from_tb(TranslationBlock *tb, uintptr_t host_pc,
                                   uint64_t *data)
{
    uintptr_t iter_pc = (uintptr_t)tb->tc.ptr;
    const uint8_t *p = tb->tc.search;
    int i, j, num_insns = tb->icount;

    host_pc -= GETPC_ADJ;

    if (host_pc < iter_pc) {
        return -1;
    }

    memset(data, 0, sizeof(uint64_t) * INSN_START_WORDS);
    if (!(tb_cflags(tb) & CF_PCREL)) {
        data[0] = tb->pc;
    }

    /*
     * Reconstruct the stored insn data while looking for the point
     * at which the end of the insn exceeds host_pc.
     */
    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        iter_pc += decode_sleb128(&p);
        if (iter_pc > host_pc) {
            return num_insns - i;
        }
    }
    return -1;
}

/*
 * The cpu state corresponding to 'host_pc' is restored in
 * preparation for exiting the TB.
 */
void cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                               uintptr_t host_pc)
{
    uint64_t data[INSN_START_WORDS];
    int insns_left = cpu_unwind_data_from_tb(tb, host_pc, data);

    if (insns_left < 0) {
        return;
    }

    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        assert(icount_enabled());
        /*
         * Reset the cycle counter to the start of the block and
         * shift if to the number of actually executed instructions.
         */
        cpu->neg.icount_decr.u16.low += insns_left;
    }

    cpu->cc->tcg_ops->restore_state_to_opc(cpu, tb, data);
}

bool cpu_restore_state(CPUState *cpu, uintptr_t host_pc)
{
    /*
     * The host_pc has to be in the rx region of the code buffer.
     * If it is not we will not be able to resolve it here.
     * The two cases where host_pc will not be correct are:
     *
     *  - fault during translation (instruction fetch)
     *  - fault from helper (not using GETPC() macro)
     *
     * Either way we need return early as we can't resolve it here.
     */
    if (in_code_gen_buffer((const void *)(host_pc - tcg_splitwx_diff))) {
        TranslationBlock *tb = tcg_tb_lookup(host_pc);
        if (tb) {
            cpu_restore_state_from_tb(cpu, tb, host_pc);
            return true;
        }
    }
    return false;
}

bool cpu_unwind_state_data(CPUState *cpu, uintptr_t host_pc, uint64_t *data)
{
    if (in_code_gen_buffer((const void *)(host_pc - tcg_splitwx_diff))) {
        TranslationBlock *tb = tcg_tb_lookup(host_pc);
        if (tb) {
            return cpu_unwind_data_from_tb(tb, host_pc, data) >= 0;
        }
    }
    return false;
}

void page_init(void)
{
    page_table_config_init();
}

/*
 * Isolate the portion of code gen which can setjmp/longjmp.
 * Return the size of the generated code, or negative on error.
 */
static int setjmp_gen_code(CPUArchState *env, TranslationBlock *tb,
                           vaddr pc, void *host_pc,
                           int *max_insns, int64_t *ti)
{
    int ret = sigsetjmp(tcg_ctx->jmp_trans, 0);
    if (unlikely(ret != 0)) {
        return ret;
    }

    tcg_func_start(tcg_ctx);

    CPUState *cs = env_cpu(env);
    tcg_ctx->cpu = cs;
    cs->cc->tcg_ops->translate_code(cs, tb, max_insns, pc, host_pc);

    assert(tb->size != 0);
    tcg_ctx->cpu = NULL;
    *max_insns = tb->icount;

    /* Before any host code: the struct keeps only the slots issued. */
    tcg_tb_trim_slots(tcg_ctx, tb);
    return tcg_gen_code(tcg_ctx, tb, pc);
}

#ifdef CONFIG_USER_ONLY
/* The cflags a captured TB may have. */
#define TB_CACHE_CFLAGS  (CF_PARALLEL | CF_CLUSTER_MASK | CF_COUNT_MASK)

/*
 * The guarded routines (tcg-cache.h).  The source loads are at the
 * tcg_cache_gload* labels; nothing else in them may fault on the
 * caller's behalf, and they keep LR, SP and the callee-saved registers,
 * so that a handler can return to LR.  Results: 0 copied or equal, 1
 * different.
 */
#if defined(__aarch64__) && (defined(__linux__) || defined(_WIN32))
asm("   .text\n"
    "   .balign 16\n"
    "   .globl tcg_cache_gcopy\n"
    "tcg_cache_gcopy:\n"
    "   cmp     x2, #8\n"
    "   b.lo    2f\n"
    "1:\n"
    "   .globl tcg_cache_gload0\n"
    "tcg_cache_gload0:\n"
    "   ldr     x3, [x1], #8\n"
    "   str     x3, [x0], #8\n"
    "   sub     x2, x2, #8\n"
    "   cmp     x2, #8\n"
    "   b.hs    1b\n"
    "2:\n"
    "   cbz     x2, 4f\n"
    "3:\n"
    "   .globl tcg_cache_gload1\n"
    "tcg_cache_gload1:\n"
    "   ldrb    w3, [x1], #1\n"
    "   strb    w3, [x0], #1\n"
    "   subs    x2, x2, #1\n"
    "   b.ne    3b\n"
    "4:\n"
    "   mov     x0, #0\n"
    "   ret\n"
    "   .balign 16\n"
    "   .globl tcg_cache_gcmp\n"
    "tcg_cache_gcmp:\n"
    "   cmp     x2, #8\n"
    "   b.lo    2f\n"
    "1:\n"
    "   .globl tcg_cache_gload2\n"
    "tcg_cache_gload2:\n"
    "   ldr     x3, [x0], #8\n"
    "   .globl tcg_cache_gload3\n"
    "tcg_cache_gload3:\n"
    "   ldr     x4, [x1], #8\n"
    "   cmp     x3, x4\n"
    "   b.ne    5f\n"
    "   sub     x2, x2, #8\n"
    "   cmp     x2, #8\n"
    "   b.hs    1b\n"
    "2:\n"
    "   cbz     x2, 4f\n"
    "3:\n"
    "   .globl tcg_cache_gload4\n"
    "tcg_cache_gload4:\n"
    "   ldrb    w3, [x0], #1\n"
    "   .globl tcg_cache_gload5\n"
    "tcg_cache_gload5:\n"
    "   ldrb    w4, [x1], #1\n"
    "   cmp     w3, w4\n"
    "   b.ne    5f\n"
    "   subs    x2, x2, #1\n"
    "   b.ne    3b\n"
    "4:\n"
    "   mov     x0, #0\n"
    "   ret\n"
    "5:\n"
    "   mov     x0, #1\n"
    "   ret\n"
    "   .data\n"
    "   .balign 8\n"
    "   .globl tcg_cache_gloads\n"
    "tcg_cache_gloads:\n"
    "   .quad   tcg_cache_gload0, tcg_cache_gload1, tcg_cache_gload2\n"
    "   .quad   tcg_cache_gload3, tcg_cache_gload4, tcg_cache_gload5\n"
    "   .text\n");

bool tcg_cache_guard_pc(uintptr_t pc)
{
    for (int i = 0; i < TCG_CACHE_GLOADS; i++) {
        if (pc == tcg_cache_gloads[i]) {
            return true;
        }
    }
    return false;
}
#else
int64_t tcg_cache_gcopy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return 0;
}

int64_t tcg_cache_gcmp(const void *a, const void *b, size_t len)
{
    return memcmp(a, b, len) != 0;
}

bool tcg_cache_guard_pc(uintptr_t pc)
{
    return false;
}
#endif

int tcg_cache_selftest(uint8_t *p, size_t page)
{
    static const size_t lens[] = { 0, 1, 7, 8, 9, 15, 16, 17, 63, 200 };
    uint8_t *ref = g_malloc(page), *dst = g_malloc(page + 64);
    int fails = 0, checks = 0;
    int64_t r;

#define SELFCHECK(cond, ...) do {                                      \
        checks++;                                                       \
        if (!(cond)) {                                                  \
            fails++;                                                    \
            fprintf(stderr, "xtcg-cache selftest: " __VA_ARGS__);       \
        }                                                               \
    } while (0)

    for (size_t i = 0; i < page; i++) {
        p[i] = ref[i] = i * 37 + 11;
    }
    /* Lengths and alignments, within the readable page. */
    for (int a = 0; a < 8; a++) {
        for (int l = 0; l < ARRAY_SIZE(lens); l++) {
            size_t n = lens[l];

            memset(dst, 0xee, page + 64);
            r = tcg_cache_gcopy(dst + a, p + a + 3, n);
            SELFCHECK(r == 0 && !memcmp(dst + a, ref + a + 3, n) &&
                      dst[a + n] == 0xee,
                      "copy align %d len %zu: %" PRIx64 "\n", a, n, r);
            r = tcg_cache_gcmp(p + a, ref + a, n);
            SELFCHECK(r == 0, "cmp equal align %d len %zu: %" PRIx64 "\n",
                      a, n, r);
            if (n) {
                ref[a + n - 1] ^= 1;
                r = tcg_cache_gcmp(p + a, ref + a, n);
                SELFCHECK(r == 1, "cmp differ (last) align %d len %zu: %"
                          PRIx64 "\n", a, n, r);
                r = tcg_cache_gcmp(ref + a, p + a, n);
                SELFCHECK(r == 1, "cmp differ (swapped) align %d len %zu: %"
                          PRIx64 "\n", a, n, r);
                ref[a + n - 1] ^= 1;
            }
        }
    }
    /*
     * Across into the inaccessible page: a fault code whose address is in
     * the access that crossed (an access that straddles the boundary may
     * report its own start).
     */
    for (int t = 1; t <= 17; t += 8) {
        uint8_t *src = p + page - t;
        uintptr_t lo = (uintptr_t)(p + page - 8), hi = (uintptr_t)(p + page);

#define FAULTED(r) ((uint64_t)(r) >> 62 == 2 &&                         \
                    ((uint64_t)(r) & (TCG_CACHE_GFAULT_GUARD - 1)) >= lo && \
                    ((uint64_t)(r) & (TCG_CACHE_GFAULT_GUARD - 1)) <= hi)
        r = tcg_cache_gcopy(dst, src, t + 8);
        SELFCHECK(FAULTED(r) && !memcmp(dst, ref + page - t, t & ~7),
                  "copy fault tail %d: %" PRIx64 "\n", t, r);
        r = tcg_cache_gcmp(ref + page - t, src, t + 8);
        SELFCHECK(FAULTED(r), "cmp fault (second) tail %d: %" PRIx64 "\n",
                  t, r);
        r = tcg_cache_gcmp(src, ref + page - t, t + 8);
        SELFCHECK(FAULTED(r), "cmp fault (first) tail %d: %" PRIx64 "\n",
                  t, r);
#undef FAULTED
    }
#if defined(__aarch64__) && (defined(__linux__) || defined(_WIN32))
    /* Only the loads are recognised. */
    SELFCHECK(!tcg_cache_guard_pc((uintptr_t)tcg_cache_gcopy) &&
              !tcg_cache_guard_pc((uintptr_t)tcg_cache_gcmp) &&
              !tcg_cache_guard_pc(tcg_cache_gloads[0] + 4),
              "a non-load PC is recognised\n");
#endif
#undef SELFCHECK
    fprintf(stderr, "xtcg-cache selftest: %d of %d checks failed\n", fails,
            checks);
    g_free(ref);
    g_free(dst);
    return fails;
}

/*
 * TCG_CACHE_ON in qemu-user (testing).  A page is eligible when its
 * translations are never SMC-checked (PAGE_FIXED_CODE: a private mapping)
 * and nothing can write it (neither PAGE_WRITE nor PAGE_WRITE_ORG); the
 * key is its absolute address.  The guarded routines contain a fault
 * from a mapping whose backing went (a truncated file).  The OS layer
 * may provide its own (tcg_cache_host).
 */
static bool tb_cache_page_image(vaddr page, TCGCacheImage *img)
{
    int want = PAGE_VALID | PAGE_EXEC | PAGE_FIXED_CODE;

    if ((page_get_flags(page) & (want | PAGE_WRITE | PAGE_WRITE_ORG))
        != want) {
        return false;
    }
    img->id = tcg_cache_test_img_shift ? page >> tcg_cache_test_img_shift : 0;
    img->base = 0;
    return true;
}

static void tb_cache_fault(int64_t code)
{
}

static const TCGCacheHost tb_cache_host_user = {
    .page_image = tb_cache_page_image,
    .copy = tcg_cache_gcopy,
    .compare = tcg_cache_gcmp,
    .fault = tb_cache_fault,
};

static const TCGCacheHost *tb_cache_host(void)
{
    return tcg_cache_host ? tcg_cache_host : &tb_cache_host_user;
}

/*
 * Install the TB for @s from artifact @art, as a fresh translation is
 * published: NULL if it doesn't apply here (the reason counted), else the
 * TB, or one an other thread published for the same key first.  With
 * @img (TCG_CACHE_ON), @art came from the store for @s.pc's page, which is
 * eligible and in @img: the rest of its pages must be too, and no adaptive
 * state may have changed what translation would give.  Called with
 * mmap_lock held.
 */
/* Why the last install failed (TCG_CACHE_W_*), and the last lookup. */
static unsigned tb_cache_fail, tb_cache_why;

static TranslationBlock *tb_cache_install(CPUState *cpu, TCGTBCPUState s,
                                          tb_page_addr_t phys_pc,
                                          const void *art, size_t len,
                                          const TCGCacheImage *img)
{
    int64_t t0 = TCG_CACHE_CLOCK(), t1, t2;
    const TCGCacheHost *host = tb_cache_host();
    CPUArchState *env = cpu_env(cpu);
    TCGCacheArtView v;
    TCGCacheRes r;
    const TCGCacheArt *h;
    TranslationBlock *tb, *existing_tb;
    tb_page_addr_t phys_p2 = -1;
    vaddr page = s.pc & TARGET_PAGE_MASK;
    bool spans, reads_p2 = false;
    uint32_t off;

    tb_cache_fail = TCG_CACHE_W_OTHER;
    if (!tcg_cache_art_view(art, len, &v)) {
        if (img) {
            tcg_cache_stats.miss_struct++;
        } else {
            tcg_cache_stats.inst_fail_key++;
        }
        return NULL;
    }
    h = v.h;
    if (h->pc != s.pc || h->cs_base != s.cs_base || h->tb_flags != s.flags
        || h->cflags != s.cflags || !h->size) {
        if (tcg_cache_debug) {
            fprintf(stderr,
                    "key: pc %llx/%llx cs %llx/%llx fl %x/%x cf %x/%x\n",
                    (unsigned long long)h->pc, (unsigned long long)s.pc,
                    (unsigned long long)h->cs_base,
                    (unsigned long long)s.cs_base, h->tb_flags, s.flags,
                    h->cflags, s.cflags);
        }
        tcg_cache_stats.inst_fail_key++;
        if (h->pc != s.pc) {
            tcg_cache_stats.inst_fail_kpc++;
            tb_cache_fail = TCG_CACHE_W_KEYPC;
        } else {
            tb_cache_fail = TCG_CACHE_W_KEY;
        }
        return NULL;
    }
    spans = ((s.pc + h->size - 1) & TARGET_PAGE_MASK) != page;
    if (spans != !!(h->flags & TCG_CACHE_ART_PAGE2)) {
        tcg_cache_stats.inst_fail_key++;
        tb_cache_fail = TCG_CACHE_W_KEY;
        return NULL;
    }
    off = 0;
    for (int i = 0; i < h->n_ext; i++) {
        const TCGCacheArtExt *e = &v.ext[i];

        if (e->off + e->len > 2 * TARGET_PAGE_SIZE ||
            off + e->len > h->ext_bytes) {
            tcg_cache_stats.inst_fail_bytes++;
            return NULL;
        }
        reads_p2 |= e->off + e->len > TARGET_PAGE_SIZE;
        off += e->len;
    }

    /* Every page the translation read is eligible, in the same image. */
    if (img && (spans || reads_p2)) {
        TCGCacheImage img2;

        if (!host->page_image(page + TARGET_PAGE_SIZE, &img2) ||
            img2.id != img->id || img2.base != img->base) {
            tcg_cache_stats.miss_inel++;
            return NULL;
        }
    }
    if (spans) {
        phys_p2 = get_page_addr_code(env, page + TARGET_PAGE_SIZE);
        if (phys_p2 == -1) {
            tcg_cache_stats.inst_fail_bytes++;
            return NULL;
        }
    }

    /* Promoted since: translation gives different code now. */
    for (int i = 0; i < h->n_acq; i++) {
        if (tcg_tso_cross_promoted(v.acq[i])) {
            tcg_cache_stats.inst_fail_promoted++;
            return NULL;
        }
    }
    if (img && h->n_acq && tcg_cache_inj_promote) {
        /* Testing: a promotion racing this install. */
        while (!tcg_tso_cross_count(v.acq[0])) {
            continue;
        }
        tcg_cache_stats.inj_promote++;
    }
    /* A region head translates as a region now. */
    if (img && translator_region_is_head(phys_pc)) {
        tcg_cache_stats.miss_region++;
        return NULL;
    }

    /* The bytes the translation read are still there. */
    t1 = TCG_CACHE_CLOCK();
    tcg_cache_stats.inst_prep_ns += t1 - t0;
    off = 0;
    for (int i = 0; i < h->n_ext; i++) {
        const TCGCacheArtExt *e = &v.ext[i];
        void *g = g2h_untagged_vaddr(page + e->off);
        int64_t c;

        if (img && host->inject) {
            host->inject(page + e->off, true);
        }
        c = host->compare(g, v.ext_bytes + off, e->len);
        if (c < 0) {
            host->fault(c);
        }
        if (img && host->inject) {
            host->inject(page + e->off, false);
        }
        if (c) {
            if (c < 0) {
                if (tcg_cache_debug) {
                    fprintf(stderr, "xtcg-cache: guarded compare fault %"
                            PRIx64 " at pc %" PRIx64 "\n", c, (uint64_t)s.pc);
                }
                tcg_cache_stats.miss_fault++;
            } else {
                tcg_cache_stats.inst_fail_bytes++;
            }
            return NULL;
        }
        off += e->len;
    }
    tcg_cache_stats.checks++;
    t2 = TCG_CACHE_CLOCK();
    tcg_cache_stats.check_ns += t2 - t1;

    if (!tcg_cache_reserve(tcg_ctx, &v, &r)) {
        tcg_cache_stats.inst_fail_reserve++;
        return NULL;
    }
    tcg_cache_part(&tcg_cache_stats.inst_res_ns, &t2);
    tb = tcg_cache_place(tcg_ctx, &v, &r);
    tcg_cache_part(&tcg_cache_stats.inst_place_ns, &t2);
    if (!tb) {
        tcg_cache_stats.inst_fail_reloc++;
        tcg_cache_stats.inst_fail_rk[tcg_cache_fail_kind]++;
        tcg_cache_stats.inst_fail_rf[tcg_cache_fail_form]++;
        switch (tcg_cache_fail_kind) {
        case TCG_CAP_HELPER:
            tb_cache_fail = TCG_CACHE_W_HELPER;
            break;
        case TCG_CAP_STUB:
            tb_cache_fail = TCG_CACHE_W_STUB;
            break;
        case TCG_CAP_THUNK:
            tb_cache_fail = TCG_CACHE_W_THUNK;
            break;
        default:
            tb_cache_fail = TCG_CACHE_W_RELOC;
            break;
        }
        return NULL;
    }
    tb_set_page_addr0(tb, phys_pc);
    tb_lock_page0(phys_pc);
    if (phys_p2 != -1) {
        tb_set_page_addr1(tb, phys_p2);
        tb_lock_page1(phys_pc, phys_p2);
    }
    tcg_cache_part(&tcg_cache_stats.inst_link_ns, &t2);
    tcg_cache_commit(tcg_ctx, &r);
    tcg_cache_part(&tcg_cache_stats.inst_flush_ns, &t2);

    for (int n = 0; n < tb->nb_slots; n++) {
        if (tb->jmp[n].reset_offset != TB_JMP_OFFSET_INVALID) {
            tb_reset_jump(tb, n);
        }
    }
    perf_report_code(s.pc, tb, tb->tc.ptr);
    tcg_tb_insert(tb);
    existing_tb = tb_link_page(tb);
    assert_no_pages_locked();
    tcg_cache_stats.installs++;
    tcg_cache_part(&tcg_cache_stats.inst_link_ns, &t2);
    tcg_cache_stats.install_ns += TCG_CACHE_CLOCK() - t0;
    if (unlikely(existing_tb != tb)) {
        tcg_cache_stats.inst_dup++;
        qatomic_set(&tcg_ctx->code_gen_ptr,
                    r.split ? r.hot : (void *)tb);
        tcg_tb_remove(tb);
        return existing_tb;
    }
    return tb;
}

/* A file's candidate, installed if it applies (tcg_cache_file_select). */
typedef struct TBCacheUse {
    CPUState *cpu;
    TCGTBCPUState s;
    tb_page_addr_t phys_pc;
    const TCGCacheImage *img;
    TranslationBlock *tb;
    int tried;
} TBCacheUse;

static bool tb_cache_use(const TCGCacheEnv *env, void *opaque)
{
    TBCacheUse *u = opaque;
    int64_t t0 = TCG_CACHE_CLOCK();

    if (u->tried++ < tcg_cache_test_reject) {
        return false;
    }

    u->tb = tb_cache_install(u->cpu, u->s, u->phys_pc, env + 1,
                             env->len - sizeof(*env), u->img);
    if (!u->tb) {
        tcg_cache_stats.file_fail++;
        tcg_cache_stats.file_fail_ns += TCG_CACHE_CLOCK() - t0;
        tb_cache_why = tb_cache_fail;
    }
    return u->tb != NULL;
}

/*
 * TCG_CACHE_ON: the TB for @s from the store, if a candidate for @img
 * applies, else NULL.  Each candidate is copied out (guarded) and its
 * structure checked before anything in it is used.
 */
static TranslationBlock *tb_cache_lookup(CPUState *cpu, TCGTBCPUState s,
                                         tb_page_addr_t phys_pc,
                                         const TCGCacheImage *img)
{
    static void *buf;
    static size_t buf_size;
    const TCGCacheHost *host = tb_cache_host();
    TCGCacheCand c[TCG_CACHE_CANDS];
    int64_t t0 = TCG_CACHE_CLOCK(), t1;
    int n;

    tcg_cache_stats.lookups++;
    tb_cache_why = TCG_CACHE_W_NONE;
    /* The directory's files (the back end's snapshot). */
    {
        TCGCacheSnap *snap;

        RCU_READ_LOCK_GUARD();
        snap = qatomic_rcu_read(&tcg_cache_snap);
        if (qatomic_read(&tcg_cache_sink_on) && (!snap || !snap->n)) {
            /* Nothing mapped yet: others may have published since. */
            qatomic_set(&tcg_cache_file_missed, true);
        }
        if (snap && snap->n) {
            static void *sbuf;
            TBCacheUse u = { cpu, s, phys_pc, img, NULL };

            if (!sbuf) {
                sbuf = g_malloc(sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX);
            }
            tcg_cache_stats.file_lookups++;
            tcg_cache_snap_select(snap, img->id, s.pc - img->base, s.flags,
                                  s.cs_base, s.cflags, sbuf,
                                  sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX,
                                  tb_cache_use, &u,
                                  tcg_cache_stats.file_reject);
            if (u.tb) {
                tcg_cache_stats.file_hits++;
                tcg_cache_stats.hits++;
                tcg_cache_stats.hit_ns += TCG_CACHE_CLOCK() - t0;
                tcg_cache_stats.look_ns += TCG_CACHE_CLOCK() - t0;
                return u.tb;
            }
            qatomic_set(&tcg_cache_file_missed, true);
        }
    }
    /* Testing (XTCG_CACHE_LOAD): a file's artifacts first. */
    if (tcg_cache_have_loaded) {
        static void *fbuf;
        TBCacheUse u = { cpu, s, phys_pc, img, NULL };

        if (!fbuf) {
            fbuf = g_malloc(sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX);
        }
        tcg_cache_stats.file_lookups++;
        tcg_cache_file_select(&tcg_cache_loaded, img->id, s.pc - img->base,
                              s.flags, s.cs_base, s.cflags, fbuf,
                              sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX,
                              tb_cache_use, &u, tcg_cache_stats.file_reject);
        if (u.tb) {
            tcg_cache_stats.file_hits++;
            tcg_cache_stats.hits++;
            tcg_cache_stats.hit_ns += TCG_CACHE_CLOCK() - t0;
            tcg_cache_stats.look_ns += TCG_CACHE_CLOCK() - t0;
            return u.tb;
        }
    }
    n = tcg_cache_store_find(img->id, s.pc - img->base, s.flags, s.cs_base,
                             s.cflags, c);
    if (!n) {
        tcg_cache_stats.look_none++;
        tcg_cache_stats.look_ns += TCG_CACHE_CLOCK() - t0;
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        TranslationBlock *tb;
        int64_t r;

        if (c[i].base != img->base) {
            tcg_cache_stats.miss_base++;
            continue;
        }
        if (c[i].len > buf_size) {
            buf_size = ROUND_UP(c[i].len, 4096);
            g_free(buf);
            buf = g_malloc(buf_size);
        }
        t1 = TCG_CACHE_CLOCK();
        r = host->copy(buf, c[i].art, c[i].len);
        tcg_cache_stats.copies++;
        tcg_cache_stats.copy_ns += TCG_CACHE_CLOCK() - t1;
        if (r) {
            if (tcg_cache_debug) {
                fprintf(stderr, "xtcg-cache: guarded copy fault %" PRIx64
                        "\n", r);
            }
            host->fault(r);
            tcg_cache_stats.miss_fault++;
            continue;
        }
        tb = tb_cache_install(cpu, s, phys_pc, buf, c[i].len, img);
        if (tb) {
            tcg_cache_stats.hits++;
            tcg_cache_stats.hit_ns += TCG_CACHE_CLOCK() - t0;
            tcg_cache_stats.look_ns += TCG_CACHE_CLOCK() - t0;
            return tb;
        }
    }
    tcg_cache_stats.look_ns += TCG_CACHE_CLOCK() - t0;
    return NULL;
}

/* TCG_CACHE_ON: a translation's line for XTCG_CACHE_TRACE. */
static void tb_cache_trace(const TCGTBCPUState *s, const TCGCacheImage *img,
                           const char *outcome, uint64_t ghash, int64_t ns)
{
    char line[200];

    snprintf(line, sizeof(line), "xlat %016" PRIx64 " %" PRIx64 " %" PRIx64
             " %x %" PRIx64 " %x %s %016" PRIx64 " %" PRId64 "\n",
             img ? img->id : 0, (uint64_t)s->pc - (img ? img->base : 0),
             img ? img->base : 0, s->flags, (uint64_t)s->cs_base, s->cflags,
             outcome, ghash, ns);
    tcg_cache_out(line);
}

/*
 * TCG_CACHE_ON: testing, a flush every tcg_cache_flush_every translations
 * (not installs, so that a working set larger than that doesn't keep the
 * flushes going by itself).
 */
static void tb_cache_count(CPUState *cpu)
{
    static unsigned n;

    if (tcg_cache_flush_every && ++n >= tcg_cache_flush_every) {
        n = 0;
        tcg_cache_stats.flushes++;
        queue_tb_flush(cpu);
    }
}
#else
/*
 * System mode installs nothing from files; their readers, built in every
 * mode, copy with a plain one.
 */
int64_t tcg_cache_gcopy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return 0;
}
#endif

/* Called with mmap_lock held for user mode emulation.  */
TranslationBlock *tb_gen_code(CPUState *cpu, TCGTBCPUState s)
{
    CPUArchState *env = cpu_env(cpu);
    TranslationBlock *tb, *existing_tb;
    tb_page_addr_t phys_pc, phys_p2;
    tcg_insn_unit *gen_code_buf;
    int gen_code_size, search_size, max_insns;
    uint8_t *search, *search_hw;
    int64_t ti;
    void *host_pc;
#ifdef CONFIG_USER_ONLY
    void *art = NULL;
    size_t art_len = 0;
    TCGCacheImage cache_img = { };
    bool cache_elig = false;
    const char *cache_outcome = NULL;
    uint64_t cache_ghash = 0;
    int64_t cache_t0 = tcg_cache_trace ? get_clock() : 0;
    int64_t gen_t0 = 0;
    bool gen_counted = false;
#endif

    assert_memory_lock();
    qemu_thread_jit_write();
    TCG_HOST_FP_SUSPEND_GUARD(cpu);
    translator_region_start();

    phys_pc = get_page_addr_code_hostp(env, s.pc, &host_pc);

    if (phys_pc == -1) {
        /* Generate a one-shot TB with 1 insn in it */
        s.cflags = (s.cflags & ~CF_COUNT_MASK) | 1;
    }

    max_insns = s.cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = TCG_MAX_INSNS;
    }
    QEMU_BUILD_BUG_ON(CF_COUNT_MASK + 1 != TCG_MAX_INSNS);

#ifdef CONFIG_USER_ONLY
    tcg_ctx->cap_on = tcg_cache_mode && phys_pc != -1
                      && !(s.cflags & ~TB_CACHE_CFLAGS);
#ifdef CONFIG_PLUGIN
    /*
     * A plugin instruments TBs as they are translated: nothing cached may
     * stand in for a translation, and nothing translated is kept.
     */
    if (cpu->plugin_state
        && test_bit(QEMU_PLUGIN_EV_VCPU_TB_TRANS,
                    cpu->plugin_state->event_mask)) {
        tcg_ctx->cap_on = false;
    }
#endif
    if (tcg_ctx->cap_on && tcg_cache_mode == TCG_CACHE_ON) {
        cache_elig = tb_cache_host()->page_image(s.pc & TARGET_PAGE_MASK,
                                                 &cache_img);
        if (cache_elig) {
            tb = tb_cache_lookup(cpu, s, phys_pc, &cache_img);
            if (tb) {
                return tb;
            }
            gen_t0 = TCG_CACHE_CLOCK();
            gen_counted = true;
        } else {
            tcg_cache_stats.look_inel++;
            tcg_ctx->cap_on = false;
            cache_outcome = "inel";
        }
    }
#endif

 buffer_overflow:
    assert_no_pages_locked();
    tb = tcg_tb_alloc(tcg_ctx);
    if (unlikely(!tb)) {
        /* flush must be done */
        if (cpu_in_serial_context(cpu)) {
            trace_tb_gen_code_buffer_overflow("tcg_tb_alloc");
            tb_flush__exclusive_or_serial();
            goto buffer_overflow;
        }
        queue_tb_flush(cpu);
        mmap_unlock();
        /* Make the execution loop process the flush as soon as possible.  */
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }

    gen_code_buf = tcg_ctx->code_gen_ptr;
    tb->tc.ptr = tcg_splitwx_to_rx(gen_code_buf);
    if (!(s.cflags & CF_PCREL)) {
        tb->pc = s.pc;
    }
    tb->cs_base = s.cs_base;
    tb->flags = s.flags;
    tb->chain_dead_in = false;
    tb->cflags = s.cflags;
    tb->loops = false;
    tb_set_page_addr0(tb, phys_pc);
    tb_set_page_addr1(tb, -1);
    if (phys_pc != -1) {
        tb_lock_page0(phys_pc);
    }

    tcg_ctx->gen_tb = tb;
    tcg_ctx->guest_mo = cpu->cc->tcg_ops->guest_default_memory_order;

 restart_translate:
    /* A retry translates again with all the slots (tcg_tb_trim_slots). */
    tcg_tb_reserve_slots(tcg_ctx, tb);
    trace_translate_block(tb, s.pc, tb->tc.ptr);

    gen_code_size = setjmp_gen_code(env, tb, s.pc, host_pc, &max_insns, &ti);
    if (unlikely(gen_code_size < 0)) {
        switch (gen_code_size) {
        case -1:
            trace_tb_gen_code_buffer_overflow("setjmp_gen_code");
            /*
             * Overflow of code_gen_buffer, or the current slice of it.
             *
             * TODO: We don't need to re-do tcg_ops->translate_code, nor
             * should we re-do the tcg optimization currently hidden
             * inside tcg_gen_code.  All that should be required is to
             * flush the TBs, allocate a new TB, re-initialize it per
             * above, and re-do the actual code generation.
             */
            qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                          "Restarting code generation for "
                          "code_gen_buffer overflow\n");
            tb_unlock_pages(tb);
            tcg_ctx->gen_tb = NULL;
            goto buffer_overflow;

        case -2:
            /*
             * The code generated for the TranslationBlock is too large.
             * The maximum size allowed by the unwind info is 64k.
             * There may be stricter constraints from relocations
             * in the tcg backend.
             *
             * Try again with half as many insns as we attempted this time.
             * If a single insn overflows, there's a bug somewhere...
             * A multi-block region tries fewer blocks first.
             */
            if (translator_region_overflow()) {
                qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                              "Restarting code generation with a smaller "
                              "region\n");
                max_insns = s.cflags & CF_COUNT_MASK ?: TCG_MAX_INSNS;
                phys_p2 = tb_page_addr1(tb);
                if (unlikely(phys_p2 != -1)) {
                    tb_unlock_page1(phys_pc, phys_p2);
                    tb_set_page_addr1(tb, -1);
                }
                goto restart_translate;
            }
            assert(max_insns > 1);
            max_insns /= 2;
            qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                          "Restarting code generation with "
                          "smaller translation block (max %d insns)\n",
                          max_insns);

            /*
             * The half-sized TB may not cross pages.
             * TODO: Fix all targets that cross pages except with
             * the first insn, at which point this can't be reached.
             */
            phys_p2 = tb_page_addr1(tb);
            if (unlikely(phys_p2 != -1)) {
                tb_unlock_page1(phys_pc, phys_p2);
                tb_set_page_addr1(tb, -1);
            }
            goto restart_translate;

        case -3:
            /*
             * We had a page lock ordering problem.  In order to avoid
             * deadlock we had to drop the lock on page0, which means
             * that everything we translated so far is compromised.
             * Restart with locks held on both pages.
             */
            qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                          "Restarting code generation with re-locked pages");
            goto restart_translate;

        case -4:
            /* tcg_tblayout: code too far from code it branches to. */
            qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                          "Restarting code generation without cold code\n");
            goto restart_translate;

        default:
            g_assert_not_reached();
        }
    }
    /* tcg_tb_trim_slots may have moved the code start (packed layout). */
    gen_code_buf = (void *)tcg_splitwx_to_rw(tb->tc.ptr);
    translator_region_reset();
    tcg_ctx->gen_tb = NULL;

    /*
     * The unwind data follows the code, or with tcg_tblayout goes to the
     * chunk's cold part with the TB struct: then nothing but code and its
     * constant pool sits between one TB's code and the next.
     */
    if (tcg_ctx->lay_on) {
        search = tcg_ctx->lay_cold;
        search_hw = tcg_tb_data_highwater(tcg_ctx);
    } else {
        search = (uint8_t *)gen_code_buf + gen_code_size;
        search_hw = tcg_ctx->code_gen_highwater;
    }
    search_size = encode_search(tb, search, search_hw);
    if (unlikely(search_size < 0)) {
        trace_tb_gen_code_buffer_overflow("encode_search");
        tb_unlock_pages(tb);
        if (tcg_ctx->lay_on) {
            /* tcg_tblayout: the chunk's hot or cold part is full. */
            tcg_ctx->lay_hot_end = tcg_ctx->lay_chunk;
        }
        goto buffer_overflow;
    }
    tb->tc.size = gen_code_size;
    tb->tc.search = tcg_splitwx_to_rx(search);
#ifdef CONFIG_USER_ONLY
    if (tb->smc_inline) {
        tb->smc_check_end = tcg_ctx->insn0_off;
        tb->smc_stale = tcg_ctx->smc_stale->u.value_ptr;
    }
    if (tcg_ctx->cap_on) {
        art = tcg_cache_capture(tcg_ctx, tb, search, search_size, &art_len);
        tcg_ctx->cap_on = false;
        if (!art) {
            cache_outcome = tcg_cache_x_names[tcg_cache_last_reason];
        }
    }
#endif
    if (tcg_ctx->lay_on) {
        tcg_ctx->lay_cold = (void *)ROUND_UP((uintptr_t)search + search_size,
                                             CODE_GEN_ALIGN);
        search_size = 0;
    }

    /*
     * For CF_PCREL, attribute all executions of the generated code
     * to its first mapping.
     */
    perf_report_code(s.pc, tb, tcg_splitwx_to_rx(gen_code_buf));

    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM) &&
        qemu_log_in_addr_range(s.pc)) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            int code_size, data_size;
            const tcg_target_ulong *rx_data_gen_ptr;
            size_t chunk_start;
            int insn = 0;

            if (tcg_ctx->data_gen_ptr) {
                rx_data_gen_ptr = tcg_splitwx_to_rx(tcg_ctx->data_gen_ptr);
                code_size = (const void *)rx_data_gen_ptr - tb->tc.ptr;
                data_size = gen_code_size - code_size;
            } else {
                rx_data_gen_ptr = 0;
                code_size = gen_code_size;
                data_size = 0;
            }

            /* Dump header and the first instruction */
            fprintf(logfile, "OUT: [size=%d]\n", gen_code_size);
            fprintf(logfile,
                    "  -- guest addr 0x%016" PRIx64 " + tb prologue\n",
                    tcg_ctx->gen_insn_data[insn * INSN_START_WORDS]);
            chunk_start = tcg_ctx->gen_insn_end_off[insn];
            disas(logfile, tb->tc.ptr, chunk_start);

            /*
             * Dump each instruction chunk, wrapping up empty chunks into
             * the next instruction. The whole array is offset so the
             * first entry is the beginning of the 2nd instruction.
             */
            while (insn < tb->icount) {
                size_t chunk_end = tcg_ctx->gen_insn_end_off[insn];
                if (chunk_end > chunk_start) {
                    fprintf(logfile, "  -- guest addr 0x%016" PRIx64 "\n",
                            tcg_ctx->gen_insn_data[insn * INSN_START_WORDS]);
                    disas(logfile, tb->tc.ptr + chunk_start,
                          chunk_end - chunk_start);
                    chunk_start = chunk_end;
                }
                insn++;
            }

            if (chunk_start < code_size) {
                fprintf(logfile, "  -- tb slow paths + alignment\n");
                disas(logfile, tb->tc.ptr + chunk_start,
                      code_size - chunk_start);
            }

            /* Finally dump any data we may have after the block */
            if (data_size) {
                int i;
                fprintf(logfile, "  data: [size=%d]\n", data_size);
                for (i = 0; i < data_size / sizeof(tcg_target_ulong); i++) {
                    if (sizeof(tcg_target_ulong) == 8) {
                        fprintf(logfile,
                                "0x%08" PRIxPTR ":  .quad  0x%016" TCG_PRIlx "\n",
                                (uintptr_t)&rx_data_gen_ptr[i], rx_data_gen_ptr[i]);
                    } else if (sizeof(tcg_target_ulong) == 4) {
                        fprintf(logfile,
                                "0x%08" PRIxPTR ":  .long  0x%08" TCG_PRIlx "\n",
                                (uintptr_t)&rx_data_gen_ptr[i], rx_data_gen_ptr[i]);
                    } else {
                        qemu_build_not_reached();
                    }
                }
            }
            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }

    qatomic_set(&tcg_ctx->code_gen_ptr, (void *)
        ROUND_UP((uintptr_t)gen_code_buf + gen_code_size + search_size,
                 CODE_GEN_ALIGN));

#ifdef CONFIG_USER_ONLY
    if (tcg_cache_mode == TCG_CACHE_ON) {
        tcg_cache_stats.translations++;
        if (gen_counted) {
            tcg_cache_stats.gen[tb_cache_why]++;
            tcg_cache_stats.gen_ns[tb_cache_why] += TCG_CACHE_CLOCK() - gen_t0;
        }
        tb_cache_count(cpu);
    }
    if (tcg_cache_mode == TCG_CACHE_ON && tcg_cache_trace && !art) {
        tb_cache_trace(&s, cache_elig ? &cache_img : NULL,
                       cache_outcome ? cache_outcome : "nocap", 0,
                       get_clock() - cache_t0);
    }
    /*
     * XTCG_CACHE=stress: publish a copy installed from the artifact
     * instead, and poison the translation, which is never published.
     */
    if (art) {
        TranslationBlock *itb = NULL;

        if (tcg_cache_mode == TCG_CACHE_STRESS) {
            itb = tb_cache_install(cpu, s, phys_pc, art, art_len, NULL);
        }
        if (tcg_cache_mode == TCG_CACHE_ON) {
            TCGCacheImage img2;
            TCGCacheArtView v;
            vaddr page = s.pc & TARGET_PAGE_MASK;
            bool p2 = ((s.pc + tb->size - 1) & TARGET_PAGE_MASK) != page;

            /*
             * The second page, if the TB or the bytes it read reach it, is
             * eligible and in the same image.
             */
            if (tcg_cache_art_view(art, art_len, &v)) {
                for (int i = 0; i < v.h->n_ext; i++) {
                    p2 |= v.ext[i].off + v.ext[i].len > TARGET_PAGE_SIZE;
                }
            }
            if (cache_elig &&
                (!p2 ||
                 (tb_cache_host()->page_image(page + TARGET_PAGE_SIZE,
                                              &img2) &&
                  img2.id == cache_img.id && img2.base == cache_img.base))) {
                cache_ghash = tcg_cache_art_ghash(art, art_len);
                cache_outcome = tcg_cache_store_put(&cache_img, art, art_len);
                /* A new artifact, still the store's: to the files too. */
                if (qatomic_read(&tcg_cache_sink_on)
                    && !strcmp(cache_outcome, "stored")) {
                    tcg_cache_sink_put(cache_img.id, s.pc - cache_img.base,
                                       tcg_cache_born, art, art_len,
                                       get_clock());
                }
            } else {
                tcg_cache_stats.inel_capture++;
                cache_outcome = "inel2";
                g_free(art);
            }
            art = NULL;
            if (tcg_cache_trace) {
                tb_cache_trace(&s, &cache_img, cache_outcome, cache_ghash,
                               get_clock() - cache_t0);
            }
        }
        g_free(art);
        if (itb) {
            memset(gen_code_buf, 0, gen_code_size);
            flush_idcache_range((uintptr_t)tb->tc.ptr,
                                (uintptr_t)gen_code_buf, gen_code_size);
            if (tcg_ctx->cap_cold) {
                size_t n = (uint8_t *)tcg_ctx->cap_cold_end
                           - (uint8_t *)tcg_ctx->cap_cold;

                memset(tcg_ctx->cap_cold, 0, n);
                flush_idcache_range(
                    (uintptr_t)tcg_splitwx_to_rx(tcg_ctx->cap_cold),
                    (uintptr_t)tcg_ctx->cap_cold, n);
            }
            memset(tb, 0x5a, tb_struct_size(tb->nb_slots));
            return itb;
        }
    }
#endif

    /* init jump list */
    qemu_spin_init(&tb->jmp_lock);
    tb->jmp_list_head = (uintptr_t)NULL;
    for (int n = 0; n < tb->nb_slots; n++) {
        tb->jmp[n].list_next = (uintptr_t)NULL;
        tb->jmp[n].dest = (uintptr_t)NULL;
        /* original jump addresses, set during tcg_gen_code() */
        if (tb->jmp[n].reset_offset != TB_JMP_OFFSET_INVALID) {
            tb_reset_jump(tb, n);
        }
    }

    /*
     * Insert TB into the corresponding region tree before publishing it
     * through QHT. Otherwise rewinding happened in the TB might fail to
     * lookup itself using host PC.
     */
    tcg_tb_insert(tb);

    /*
     * If the TB is not associated with a physical RAM page then it must be
     * a temporary one-insn TB.
     *
     * Such TBs must be added to region trees in order to make sure that
     * restore_state_to_opc() - which on some architectures is not limited to
     * rewinding, but also affects exception handling! - is called when such a
     * TB causes an exception.
     *
     * At the same time, temporary one-insn TBs must be executed at most once,
     * because subsequent reads from, e.g., I/O memory may return different
     * values. So return early before attempting to link to other TBs or add
     * to the QHT.
     */
    if (tb_page_addr0(tb) == -1) {
        assert_no_pages_locked();
        return tb;
    }

    /*
     * No explicit memory barrier is required -- tb_link_page() makes the
     * TB visible in a consistent state.
     */
    existing_tb = tb_link_page(tb);
    assert_no_pages_locked();

    /* if the TB already exists, discard what we just translated */
    if (unlikely(existing_tb != tb)) {
        /*
         * Give back the TB and its code: tcg_tb_alloc put the TB first,
         * or with tcg_tblayout elsewhere (its cold part stays used).
         */
        qatomic_set(&tcg_ctx->code_gen_ptr,
                    tcg_ctx->lay_on ? tcg_splitwx_to_rw(tb->tc.ptr)
                                    : (void *)tb);
        tcg_tb_remove(tb);
        return existing_tb;
    }
    return tb;
}

/* user-mode: call with mmap_lock held */
void tb_check_watchpoint(CPUState *cpu, uintptr_t retaddr)
{
    TranslationBlock *tb;

    assert_memory_lock();

    tb = tcg_tb_lookup(retaddr);
    if (tb) {
        /* We can use retranslation to find the PC.  */
        cpu_restore_state_from_tb(cpu, tb, retaddr);
        tb_phys_invalidate(tb, -1);
    } else {
        /* The exception probably happened in a helper.  The CPU state should
           have been saved before calling it. Fetch the PC from there.  */
        CPUArchState *env = cpu_env(cpu);
        TCGTBCPUState s = cpu->cc->tcg_ops->get_tb_cpu_state(cpu);
        tb_page_addr_t addr = get_page_addr_code(env, s.pc);

        if (addr != -1) {
            tb_invalidate_phys_range(cpu, addr, addr);
        }
    }
}

/*
 * The guest pcs of instructions that did I/O from the middle of a TB
 * (tcg_iolast): an insert-only, lock-free open-addressed set.  An entry
 * is pc + 1, so that 0 means empty.  When the set is full, an
 * instruction keeps the cpu_io_recompile path.
 */
#define TB_IO_INSN_BITS  12
#define TB_IO_INSN_MASK  ((1 << TB_IO_INSN_BITS) - 1)
#define TB_IO_INSN_PROBE 16

static uint64_t tb_io_insns[1 << TB_IO_INSN_BITS];

static unsigned tb_io_insn_hash(uint64_t key)
{
    return (key * 0x9e3779b97f4a7c15ull) >> (64 - TB_IO_INSN_BITS);
}

bool tb_io_insn_known(vaddr pc)
{
    uint64_t key = (uint64_t)pc + 1;
    unsigned h = tb_io_insn_hash(key);

    for (int i = 0; i < TB_IO_INSN_PROBE; i++) {
        uint64_t e = qatomic_read(&tb_io_insns[(h + i) & TB_IO_INSN_MASK]);

        if (e == key) {
            return true;
        }
        if (e == 0) {
            return false;
        }
    }
    return false;
}

#ifndef CONFIG_USER_ONLY
/* Add @pc to the set; false if the set has no room for it. */
static bool tb_io_insn_add(vaddr pc)
{
    uint64_t key = (uint64_t)pc + 1;
    unsigned h = tb_io_insn_hash(key);

    for (int i = 0; i < TB_IO_INSN_PROBE; i++) {
        uint64_t *slot = &tb_io_insns[(h + i) & TB_IO_INSN_MASK];
        uint64_t e = qatomic_cmpxchg(slot, 0, key);

        if (e == 0 || e == key) {
            trace_tb_io_insn_add(pc, e == 0);
            return true;
        }
    }
    trace_tb_io_insn_add(pc, false);
    return false;
}

/*
 * In deterministic execution mode, instructions doing device I/Os
 * must be at the end of the TB.
 *
 * Called by softmmu_template.h, with iothread mutex not held.
 */
/*
 * tcg_iolazy: whether the guest insn whose code @retaddr is in is the last
 * of its TB, where can_do_io would be true.  True where @retaddr names no
 * TB: outside generated code, where cpu_exec leaves can_do_io true, and
 * for a helper that passed no return address (where can_do_io could be
 * false, but cpu_io_recompile would find no TB to unwind).
 */
bool cpu_io_last_insn(uintptr_t retaddr)
{
    uint64_t data[INSN_START_WORDS];
    TranslationBlock *tb;

    if (!in_code_gen_buffer((const void *)(retaddr - tcg_splitwx_diff))) {
        return true;
    }
    tb = tcg_tb_lookup(retaddr);
    if (!tb) {
        return true;
    }
    /*
     * tcg_edge_sys: only where every exit checks, so that an interrupt
     * the access makes pending is taken right after the insn.
     */
    return cpu_unwind_data_from_tb(tb, retaddr, data) == 1 &&
           (!tcg_edge_sys || tb->edge_end);
}

bool cpu_io_edge_ok(uintptr_t retaddr)
{
    TranslationBlock *tb;

    if (!tcg_edge_sys ||
        !in_code_gen_buffer((const void *)(retaddr - tcg_splitwx_diff))) {
        return true;
    }
    tb = tcg_tb_lookup(retaddr);
    return !tb || tb->edge_end;
}

void cpu_io_recompile(CPUState *cpu, uintptr_t retaddr)
{
    TranslationBlock *tb;
    const CPUClass *cc = cpu->cc;
    uint32_t n;

    tb = tcg_tb_lookup(retaddr);
    if (!tb) {
        cpu_abort(cpu, "cpu_io_recompile: could not find TB for pc=%p",
                  (void *)retaddr);
    }
    cpu_restore_state_from_tb(cpu, tb, retaddr);
    if (translator_region_io(tb)) {
        tb_phys_invalidate(tb, -1);
    }

    /*
     * With tcg_iolast, the next translation ends a TB after this
     * instruction, so that its accesses don't come back here: drop the
     * TB that has it in the middle.
     */
    if (tcg_iolast && !icount_enabled() && tb_io_insn_add(cc->get_pc(cpu))) {
        tb_phys_invalidate(tb, -1);
    }

    /*
     * Some guests must re-execute the branch when re-executing a delay
     * slot instruction.  When this is the case, adjust icount and N
     * to account for the re-execution of the branch.
     */
    n = 1;
    if (cc->tcg_ops->io_recompile_replay_branch &&
        cc->tcg_ops->io_recompile_replay_branch(cpu, tb)) {
        cpu->neg.icount_decr.u16.low++;
        n = 2;
    }

    /*
     * Exit the loop and potentially generate a new TB executing the
     * just the I/O insns. We also limit instrumentation to memory
     * operations only (which execute after completion) so we don't
     * double instrument the instruction. Also don't let an IRQ sneak
     * in before we execute it.
     */
    cpu->cflags_next_tb = curr_cflags(cpu) | CF_MEMI_ONLY | CF_NOIRQ | n;

    if (qemu_loglevel_mask(CPU_LOG_EXEC)) {
        vaddr pc = cpu->cc->get_pc(cpu);
        if (qemu_log_in_addr_range(pc)) {
            qemu_log("cpu_io_recompile: rewound execution of TB to %016"
                     VADDR_PRIx "\n", pc);
        }
    }

    cpu_loop_exit_noexc(cpu);
}

#endif /* CONFIG_USER_ONLY */

/*
 * Called by generic code at e.g. cpu reset after cpu creation,
 * therefore we must be prepared to allocate the jump cache.
 */
void tcg_retstack_reset(CPUState *cpu)
{
    CPUJumpCache *jc = cpu->tb_jmp_cache;

    if (jc && jc->retring) {
        memset(jc->retring, 0, TCG_RETSTACK_SIZE);
        *(uintptr_t *)((char *)cpu_env(cpu) + tcg_retsp_off) =
            (uintptr_t)jc->retring + TCG_RETSTACK_SIZE / 2;
    }
}

/* tcg_retstack_env: entries pushed before now are no longer good. */
void tcg_retstack_bump(CPUState *cpu)
{
    if (tcg_retstack_env) {
        uint64_t *ep = (uint64_t *)((char *)cpu_env(cpu) + tcg_retep_off);

        qatomic_set(ep, *ep + TCG_RETSTACK_TAGS);
    }
}

uintptr_t tcg_retstack_fault(CPUState *cpu, uintptr_t pc, uintptr_t addr)
{
    CPUJumpCache *jc = cpu->tb_jmp_cache;
    uintptr_t page = qemu_real_host_page_size(), ring;

    if (!jc || !jc->retring || !tcg_retstack_access(pc)) {
        return 0;
    }
    ring = (uintptr_t)jc->retring;
    if (addr + page < ring || addr >= ring + TCG_RETSTACK_SIZE + page ||
        (addr >= ring && addr < ring + TCG_RETSTACK_SIZE)) {
        return 0;
    }
    return ring + TCG_RETSTACK_SIZE / 2;
}

static void tcg_flush_jmp_cache_1(CPUState *cpu, bool clear)
{
    CPUJumpCache *jc = cpu->tb_jmp_cache;

    /* During early initialization, the cache may not yet be allocated. */
    if (unlikely(jc == NULL)) {
        return;
    }
    tcg_retstack_reset(cpu);
    tcg_retstack_bump(cpu);

    if (tcg_jcgen) {
        int shift = cpu->cc->tcg_ops->jmp_cache_salt_shift(cpu);
        uint64_t step = 1ull << shift;
        uint64_t salt = qatomic_read(&jc->salt) + step;
        uint64_t gsalt = qatomic_read(&jc->gsalt) + step;

        /*
         * Once every 2^(63 - shift) flushes a salt comes round (into the
         * other's half), and in a mode with another shift the old
         * entries' keys may alias new pcs: clear for real then.
         */
        if (!clear && step == jc->salt_step &&
            !(salt & TB_JMP_GSALT_BASE) && (gsalt & TB_JMP_GSALT_BASE)) {
            qatomic_set(&jc->salt, salt);
            qatomic_set(&jc->gsalt, gsalt);
            return;
        }
        jc->salt_step = step;
    }
    if (tcg_jcgen) {
        qatomic_set(&jc->salt, 0);
        qatomic_set(&jc->gsalt, TB_JMP_GSALT_BASE);
    }
    for (int i = 0; i < TB_JMP_CACHE_SIZE; i++) {
        qatomic_set(&jc->array[i].tb, NULL);
    }
}

void tcg_flush_jmp_cache(CPUState *cpu)
{
    tcg_flush_jmp_cache_1(cpu, false);
}

/*
 * Clear the entries themselves, not only the salt: the TBs they point to
 * are being freed (tb_flush), and tb_lookup may read them (x-tblookup).
 */
void tcg_clear_jmp_cache(CPUState *cpu)
{
    tcg_flush_jmp_cache_1(cpu, true);
}

/*
 * Forget the entries for code on non-global pages: with tcg_jcgen, move
 * only the salt on, keeping the entries made under gsalt.
 */
void tcg_flush_jmp_cache_nonglobal(CPUState *cpu)
{
    CPUJumpCache *jc = cpu->tb_jmp_cache;
    uint64_t step, salt;

    if (unlikely(jc == NULL)) {
        return;
    }
    if (!tcg_jc_global) {
        tcg_flush_jmp_cache(cpu);
        return;
    }
    tcg_retstack_bump(cpu);
    step = 1ull << cpu->cc->tcg_ops->jmp_cache_salt_shift(cpu);
    salt = qatomic_read(&jc->salt) + step;
    if (step == jc->salt_step && !(salt & TB_JMP_GSALT_BASE)) {
        qatomic_set(&jc->salt, salt);
        return;
    }
    jc->salt_step = step;
    qatomic_set(&jc->salt, 0);
    qatomic_set(&jc->gsalt, TB_JMP_GSALT_BASE);
    for (int i = 0; i < TB_JMP_CACHE_SIZE; i++) {
        qatomic_set(&jc->array[i].tb, NULL);
    }
}
