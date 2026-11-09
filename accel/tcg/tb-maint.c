/*
 * Translation Block Maintenance
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
#include "qemu/interval-tree.h"
#include "qemu/qtree.h"
#include "exec/cputlb.h"
#include "exec/log.h"
#include "exec/page-protection.h"
#include "exec/mmap-lock.h"
#include "exec/tb-flush.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/cpu-ops.h"
#include "accel/tcg/host-fp.h"
#include "tb-internal.h"
#include "system/tcg.h"
#include "tcg/tcg.h"
#include "tcg/tcg-cache.h"
#include "tcg/tcg-ldst.h"
#include "accel/tcg/probe.h"
#include "tcg/startup.h"
#include "tb-hash.h"
#include "tb-context.h"
#include "internal-common.h"
#ifdef CONFIG_USER_ONLY
#include "user/page-protection.h"
#define runstate_is_running()  true
#else
#include "system-page-protection.h"
#include "system/runstate.h"
#endif
#include "trace.h"

/* List iterators for lists of tagged pointers in TranslationBlock. */
#define TB_FOR_EACH_TAGGED(head, tb, n, field)                          \
    for (n = (head) & TB_JMP_TAG_MASK,                                  \
         tb = (TranslationBlock *)((head) & ~TB_JMP_TAG_MASK);          \
         tb; tb = (TranslationBlock *)tb->field[n],                     \
             n = (uintptr_t)tb & TB_JMP_TAG_MASK,                       \
             tb = (TranslationBlock *)((uintptr_t)tb & ~TB_JMP_TAG_MASK))

/* A TB's address has room for the tag. */
QEMU_BUILD_BUG_ON(__alignof__(TranslationBlock) < TB_JMP_SLOTS);

#define TB_FOR_EACH_JMP(head_tb, tb, n)                                 \
    for (n = (head_tb)->jmp_list_head & TB_JMP_TAG_MASK,                \
         tb = (TranslationBlock *)((head_tb)->jmp_list_head &           \
                                   ~TB_JMP_TAG_MASK);                   \
         tb; tb = (TranslationBlock *)tb->jmp[n].list_next,             \
             n = (uintptr_t)tb & TB_JMP_TAG_MASK,                       \
             tb = (TranslationBlock *)((uintptr_t)tb & ~TB_JMP_TAG_MASK))

static bool tb_cmp(const void *ap, const void *bp)
{
    const TranslationBlock *a = ap;
    const TranslationBlock *b = bp;

    return ((tb_cflags(a) & CF_PCREL || a->pc == b->pc) &&
            a->cs_base == b->cs_base &&
            a->flags == b->flags &&
            (tb_cflags(a) & ~CF_INVALID) == (tb_cflags(b) & ~CF_INVALID) &&
            tb_page_addr0(a) == tb_page_addr0(b) &&
            tb_page_addr1(a) == tb_page_addr1(b));
}

void tb_htable_init(void)
{
    unsigned int mode = QHT_MODE_AUTO_RESIZE;

    qht_init(&tb_ctx.htable, tb_cmp, CODE_GEN_HTABLE_SIZE, mode);
}

typedef struct PageDesc PageDesc;

#ifdef CONFIG_USER_ONLY

/*
 * In user-mode page locks aren't used; mmap_lock is enough.
 */
#define assert_page_locked(pd) tcg_debug_assert(have_mmap_lock())

static inline void tb_lock_pages(const TranslationBlock *tb) { }

/*
 * For user-only, since we are protecting all of memory with a single lock,
 * and because the two pages of a TranslationBlock are always contiguous,
 * use a single data structure to record all TranslationBlocks.
 */
static IntervalTreeRoot tb_root;

/* The TB's new fields sit in padding: the struct doesn't grow. */
#if HOST_LONG_BITS == 64
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, pt_state) !=
                  offsetof(TranslationBlock, smc_inline) + 1);
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, pt_index) !=
                  offsetof(TranslationBlock, smc_crc) + 4);
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, smc_stale) !=
                  offsetof(TranslationBlock, smc_crc) + 8);
QEMU_BUILD_BUG_ON(offsetof(TranslationBlock, jmp_lock) !=
                  offsetof(TranslationBlock, smc_stale) + sizeof(void *));
#endif

/*
 * TBs linked with @defer_pages (installed from a persistent cache) wait
 * in a pending list instead of entering the tree: a start-up installs
 * tens of thousands and queries page tracking for few of them.  Their
 * pages are marked in a set; a query whose range meets a marked page
 * first enters every pending TB in the tree ("catches up").  Removing a
 * pending TB takes it off the list; its marks stay until the next
 * catch-up, which is conservative.  All under mmap_lock.
 */
#define TB_PENDING_PAGES_MAX 16384

static TranslationBlock **tb_pending;
static size_t tb_pending_n, tb_pending_cap;
/* Open addressing: page number + 1, 0 when empty; at most half full. */
static uint64_t *tb_pending_pages;
static size_t tb_pending_slots, tb_pending_npages;
/* The last page marked, + 1; 0 for none. */
static uint64_t tb_pending_memo;

static size_t tb_pending_probe(uint64_t key)
{
    size_t mask = tb_pending_slots - 1;
    size_t i = ((key * 0x9e3779b97f4a7c15ull) >> 32) & mask;

    while (tb_pending_pages[i] && tb_pending_pages[i] != key) {
        i = (i + 1) & mask;
    }
    return i;
}

static bool tb_pending_marked(uint64_t page)
{
    return tb_pending_slots &&
           tb_pending_pages[tb_pending_probe(page + 1)] == page + 1;
}

static void tb_pending_mark(uint64_t page)
{
    uint64_t key = page + 1;
    size_t i;

    if (key == tb_pending_memo) {
        return;
    }
    if (2 * (tb_pending_npages + 1) > tb_pending_slots) {
        uint64_t *old = tb_pending_pages;
        size_t old_slots = tb_pending_slots;

        tb_pending_slots = old_slots ? old_slots * 2 : 1024;
        tb_pending_pages = g_new0(uint64_t, tb_pending_slots);
        for (size_t j = 0; j < old_slots; j++) {
            if (old[j]) {
                tb_pending_pages[tb_pending_probe(old[j])] = old[j];
            }
        }
        g_free(old);
    }
    i = tb_pending_probe(key);
    if (!tb_pending_pages[i]) {
        tb_pending_pages[i] = key;
        tb_pending_npages++;
    }
    tb_pending_memo = key;
}

static void tb_pending_clear(void)
{
    tb_pending_n = 0;
    if (tb_pending_npages) {
        memset(tb_pending_pages, 0, tb_pending_slots * sizeof(uint64_t));
        tb_pending_npages = 0;
    }
    tb_pending_memo = 0;
}

size_t tb_pending_count(void)
{
    return tb_pending_n;
}

/*
 * Testing (tcg_cache_test_pt_verify): a shadow of every TB in page
 * tracking, pending or in the tree, with its interval computed from its
 * start and size.  Each query's result from the tree, after its catch-up
 * decision, must be exactly the shadow's TBs that overlap the range.
 */
typedef struct PtShadow {
    vaddr start, last;
} PtShadow;

static GHashTable *pt_shadow;

static void pt_shadow_add(TranslationBlock *tb)
{
    PtShadow *e;

    if (!tcg_cache_test_pt_verify) {
        return;
    }
    if (!pt_shadow) {
        pt_shadow = g_hash_table_new_full(NULL, NULL, NULL, g_free);
    }
    e = g_new(PtShadow, 1);
    e->start = tb_page_addr0(tb);
    e->last = e->start + tb->size - 1;
    g_hash_table_insert(pt_shadow, tb, e);
}

static void pt_shadow_remove(TranslationBlock *tb)
{
    if (pt_shadow) {
        g_hash_table_remove(pt_shadow, tb);
    }
}

static void G_NORETURN pt_verify_fail(const char *why, TranslationBlock *tb,
                                      vaddr start, vaddr last)
{
    fprintf(stderr, "xtcg-cache: page tracking verify: %s: TB %p pc %"
            VADDR_PRIx " [%" VADDR_PRIx ", %" VADDR_PRIx "] state %d,"
            " query [%" VADDR_PRIx ", %" VADDR_PRIx "]\n", why, tb, tb->pc,
            (vaddr)tb->itree.start, (vaddr)tb->itree.last, tb->pt_state,
            start, last);
    abort();
}

static void pt_verify(vaddr start, vaddr last)
{
    GHashTable *seen;
    GHashTableIter it;
    gpointer k, v;

    if (!pt_shadow) {
        return;
    }
    seen = g_hash_table_new(NULL, NULL);
    for (IntervalTreeNode *n = interval_tree_iter_first(&tb_root, start, last);
         n; n = interval_tree_iter_next(n, start, last)) {
        TranslationBlock *tb = container_of(n, TranslationBlock, itree);
        PtShadow *e = g_hash_table_lookup(pt_shadow, tb);

        if (!e) {
            pt_verify_fail("in the tree, not in the shadow", tb, start, last);
        }
        if (e->start != n->start || e->last != n->last) {
            pt_verify_fail("interval differs", tb, start, last);
        }
        g_hash_table_add(seen, tb);
    }
    g_hash_table_iter_init(&it, pt_shadow);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        PtShadow *e = v;

        if (e->start <= last && e->last >= start &&
            !g_hash_table_contains(seen, k)) {
            pt_verify_fail("overlaps, not found", k, start, last);
        }
    }
    g_hash_table_destroy(seen);
    tcg_cache_stats.pt_verified++;
}

/* Enter every pending TB in the tree. */
static void tb_pending_catch_up(void)
{
    tcg_cache_stats.pt_caught += tb_pending_n;
    for (size_t i = 0; i < tb_pending_n; i++) {
        TranslationBlock *tb = tb_pending[i];

        tb->pt_state = TB_PT_IN_TREE;
        interval_tree_insert(&tb->itree, &tb_root);
    }
    tb_pending_clear();
}

/* Whether [@start, @last] meets a page of a pending TB. */
static bool tb_pending_meets(vaddr start, vaddr last)
{
    uint64_t p0 = start >> TARGET_PAGE_BITS, p1 = last >> TARGET_PAGE_BITS;

    if (!tb_pending_n) {
        /* Removals emptied the list: its marks are all stale. */
        tb_pending_clear();
        return false;
    }
    if (p1 - p0 < tb_pending_npages) {
        for (uint64_t p = p0; p <= p1; p++) {
            if (tb_pending_marked(p)) {
                return true;
            }
        }
        return false;
    }
    for (size_t i = 0; i < tb_pending_slots; i++) {
        uint64_t key = tb_pending_pages[i];

        if (key && key - 1 >= p0 && key - 1 <= p1) {
            return true;
        }
    }
    return false;
}

static void tb_pending_add(TranslationBlock *tb)
{
    if (!tb_pending_n) {
        tb_pending_clear();
    }
    /*
     * Admit the TB's pages whole, or catch up first.  Room for two pages
     * is reserved whatever the TB needs: cheaper than counting which are
     * new, at the cost of catching up a little early near the bound.
     */
    if (tb_pending_npages + 2 > (tcg_cache_test_pt_cap ?: TB_PENDING_PAGES_MAX)
        || tb_pending_n >= UINT32_MAX) {
        tcg_cache_stats.pt_catch_cap++;
        tb_pending_catch_up();
    }
    if (tb_pending_n == tb_pending_cap) {
        tb_pending_cap = tb_pending_cap ? tb_pending_cap * 2 : 1024;
        tb_pending = g_renew(TranslationBlock *, tb_pending, tb_pending_cap);
    }
    tb->pt_state = TB_PT_PENDING;
    tb->pt_index = tb_pending_n;
    tb_pending[tb_pending_n++] = tb;
    tb_pending_mark(tb->itree.start >> TARGET_PAGE_BITS);
    tb_pending_mark(tb->itree.last >> TARGET_PAGE_BITS);
    tcg_cache_stats.pt_pending_peak = MAX(tcg_cache_stats.pt_pending_peak,
                                          tb_pending_n);
    tcg_cache_stats.pt_pages_peak = MAX(tcg_cache_stats.pt_pages_peak,
                                        tb_pending_npages);
}

static void tb_remove_all(void)
{
    /*
     * Only called from tb_flush__exclusive_or_serial, where we have already
     * asserted that we're in an exclusive state.
     */
    memset(&tb_root, 0, sizeof(tb_root));
    tb_pending_clear();
    if (pt_shadow) {
        g_hash_table_remove_all(pt_shadow);
    }
}

/*
 * Call with mmap_lock held.  With @defer, the TB waits in the pending
 * list until a query meets its pages.
 */
static void tb_record(TranslationBlock *tb, bool defer)
{
    vaddr addr;
    int flags;

    assert_memory_lock();
    tb->itree.last = tb->itree.start + tb->size - 1;

    /*
     * translator_loop() must have made all TB pages non-writable, unless
     * the TB checks its bytes at entry (x-smc=check).
     */
    addr = tb_page_addr0(tb);
    flags = page_get_flags(addr);
    assert(!(flags & PAGE_WRITE) || tb->smc_check);

    addr = tb_page_addr1(tb);
    if (addr != -1) {
        flags = page_get_flags(addr);
        assert(!(flags & PAGE_WRITE) || tb->smc_check);
    }

    if (defer) {
        tb_pending_add(tb);
    } else {
        tb->pt_state = TB_PT_IN_TREE;
        interval_tree_insert(&tb->itree, &tb_root);
    }
}

/* Call with mmap_lock held. */
static void tb_remove(TranslationBlock *tb)
{
    assert_memory_lock();
    pt_shadow_remove(tb);
    if (tb->pt_state == TB_PT_PENDING) {
        TranslationBlock *moved = tb_pending[--tb_pending_n];

        g_assert(tb_pending[tb->pt_index] == tb);
        tcg_cache_stats.pt_pending_removed++;
        tb_pending[tb->pt_index] = moved;
        moved->pt_index = tb->pt_index;
    } else {
        g_assert(tb->pt_state == TB_PT_IN_TREE);
        interval_tree_remove(&tb->itree, &tb_root);
    }
    tb->pt_state = TB_PT_ABSENT;
}

/* TODO: For now, still shared with translate-all.c for system mode. */
#define PAGE_FOR_EACH_TB(start, last, pagedesc, T, N)   \
    for (T = foreach_tb_first(start, last),             \
         N = foreach_tb_next(T, start, last);           \
         T != NULL;                                     \
         T = N, N = foreach_tb_next(N, start, last))

typedef TranslationBlock *PageForEachNext;

static PageForEachNext foreach_tb_first(tb_page_addr_t start,
                                        tb_page_addr_t last)
{
    IntervalTreeNode *n;

    if (tb_pending_meets(start, last)) {
        tcg_cache_stats.pt_catch_query++;
        tb_pending_catch_up();
    }
    if (unlikely(tcg_cache_test_pt_verify)) {
        pt_verify(start, last);
    }
    n = interval_tree_iter_first(&tb_root, start, last);
    return n ? container_of(n, TranslationBlock, itree) : NULL;
}

static PageForEachNext foreach_tb_next(PageForEachNext tb,
                                       tb_page_addr_t start,
                                       tb_page_addr_t last)
{
    IntervalTreeNode *n;

    if (tb) {
        n = interval_tree_iter_next(&tb->itree, start, last);
        if (n) {
            return container_of(n, TranslationBlock, itree);
        }
    }
    return NULL;
}

/*
 * Testing (XTCG_CACHE_TEST_PT_SELFTEST): the pending list's rules on
 * synthetic TBs at unmapped pages, each query checked by the oracle:
 * a two-page TB admitted past the cap; a TB on the remembered last page
 * after a catch-up and after a flush; a non-last pending TB removed, then
 * the one moved into its place; stale marks once every pending TB is gone.
 */
static TranslationBlock *st_tb;
static vaddr st_base;

static void st_add(int i, int page, int off, int size)
{
    TranslationBlock *tb = &st_tb[i];

    memset(tb, 0, sizeof(*tb));
    tb->pc = st_base + page * TARGET_PAGE_SIZE + off;
    tb->size = size;
    tb->itree.start = tb->pc;
    tb_record(tb, true);
    pt_shadow_add(tb);
}

static int st_query(int page0, int page1)
{
    TranslationBlock *tb;
    PageForEachNext n;
    int found = 0;

    PAGE_FOR_EACH_TB(st_base + page0 * TARGET_PAGE_SIZE,
                     st_base + (page1 + 1) * TARGET_PAGE_SIZE - 1,
                     unused, tb, n) {
        found++;
    }
    return found;
}

void tb_pending_selftest(void)
{
    unsigned cap = tcg_cache_test_pt_cap;
    bool verify = tcg_cache_test_pt_verify;
    uint64_t cu_cap, cu_query;

    mmap_lock();
    /* 128 unmapped pages. */
    for (st_base = 0x20000000; ; st_base += 0x1000000) {
        int i;

        for (i = 0; i < 128; i++) {
            if (page_get_flags(st_base + i * TARGET_PAGE_SIZE)) {
                break;
            }
        }
        if (i == 128) {
            break;
        }
    }
    st_tb = g_malloc0(16 * sizeof(TranslationBlock));
    tb_remove_all();
    tcg_cache_test_pt_verify = true;
    tcg_cache_test_pt_cap = 6;

    /* Four one-page TBs, a two-page TB to the cap, one more past it. */
    for (int i = 0; i < 4; i++) {
        st_add(i, i, 16, 32);
    }
    st_add(4, 10, TARGET_PAGE_SIZE - 8, 32);
    g_assert(tb_pending_npages == 6 && tb_pending_n == 5);
    cu_cap = tcg_cache_stats.pt_catch_cap;
    st_add(5, 20, TARGET_PAGE_SIZE - 8, 32);
    g_assert(tcg_cache_stats.pt_catch_cap == cu_cap + 1);
    g_assert(st_tb[4].pt_state == TB_PT_IN_TREE);
    g_assert(st_tb[5].pt_state == TB_PT_PENDING && tb_pending_n == 1);
    g_assert(st_query(21, 21) == 1);
    g_assert(st_tb[5].pt_state == TB_PT_IN_TREE);

    /* The remembered page after a catch-up. */
    st_add(6, 30, 16, 32);
    g_assert(st_query(30, 30) == 1);
    st_add(7, 30, 64, 32);
    g_assert(st_tb[7].pt_state == TB_PT_PENDING);
    g_assert(st_query(30, 30) == 2);

    /* ... and after a flush. */
    st_add(8, 40, 16, 32);
    tb_remove_all();
    st_add(9, 40, 64, 32);
    g_assert(st_query(40, 40) == 1);

    /* A non-last pending TB removed, then the one moved into its place. */
    st_add(10, 60, 16, 32);
    st_add(11, 61, 16, 32);
    st_add(12, 62, 16, 32);
    tb_remove(&st_tb[10]);
    g_assert(st_tb[12].pt_index == 0 && tb_pending_n == 2);
    tb_remove(&st_tb[12]);
    g_assert(st_tb[11].pt_index == 0 && tb_pending_n == 1);
    g_assert(st_query(60, 60) == 0 && st_query(62, 62) == 0);
    g_assert(st_query(61, 61) == 1);

    /* Stale marks with nothing pending: no catch-up. */
    st_add(13, 70, 16, 32);
    tb_remove(&st_tb[13]);
    cu_query = tcg_cache_stats.pt_catch_query;
    g_assert(st_query(70, 70) == 0);
    g_assert(tcg_cache_stats.pt_catch_query == cu_query);
    g_assert(tb_pending_npages == 0);

    tb_remove_all();
    g_free(st_tb);
    tcg_cache_test_pt_cap = cap;
    tcg_cache_test_pt_verify = verify;
    mmap_unlock();
    fprintf(stderr, "xtcg-cache: page tracking selftest ok, %" PRIu64
            " queries verified\n", tcg_cache_stats.pt_verified);
}

#else
/*
 * In system mode we want L1_MAP to be based on ram offsets.
 */
#define L1_MAP_ADDR_SPACE_BITS  HOST_LONG_BITS

/* Size of the L2 (and L3, etc) page tables.  */
#define V_L2_BITS 10
#define V_L2_SIZE (1 << V_L2_BITS)

/*
 * L1 Mapping properties
 */
static int v_l1_size;
static int v_l1_shift;
static int v_l2_levels;

/*
 * The bottom level has pointers to PageDesc, and is indexed by
 * anything from 4 to (V_L2_BITS + 3) bits, depending on target page size.
 */
#define V_L1_MIN_BITS 4
#define V_L1_MAX_BITS (V_L2_BITS + 3)
#define V_L1_MAX_SIZE (1 << V_L1_MAX_BITS)

static void *l1_map[V_L1_MAX_SIZE];

struct PageDesc {
    QemuSpin lock;
    /* list of TBs intersecting this ram page */
    uintptr_t first_tb;
};

void page_table_config_init(void)
{
    uint32_t v_l1_bits;

    assert(TARGET_PAGE_BITS);
    /* The bits remaining after N lower levels of page tables.  */
    v_l1_bits = (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % V_L2_BITS;
    if (v_l1_bits < V_L1_MIN_BITS) {
        v_l1_bits += V_L2_BITS;
    }

    v_l1_size = 1 << v_l1_bits;
    v_l1_shift = L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - v_l1_bits;
    v_l2_levels = v_l1_shift / V_L2_BITS - 1;

    assert(v_l1_bits <= V_L1_MAX_BITS);
    assert(v_l1_shift % V_L2_BITS == 0);
    assert(v_l2_levels >= 0);
}

static PageDesc *page_find_alloc(tb_page_addr_t index, bool alloc)
{
    PageDesc *pd;
    void **lp;

    /* Level 1.  Always allocated.  */
    lp = l1_map + ((index >> v_l1_shift) & (v_l1_size - 1));

    /* Level 2..N-1.  */
    for (int i = v_l2_levels; i > 0; i--) {
        void **p = qatomic_rcu_read(lp);

        if (p == NULL) {
            void *existing;

            if (!alloc) {
                return NULL;
            }
            p = g_new0(void *, V_L2_SIZE);
            existing = qatomic_cmpxchg(lp, NULL, p);
            if (unlikely(existing)) {
                g_free(p);
                p = existing;
            }
        }

        lp = p + ((index >> (i * V_L2_BITS)) & (V_L2_SIZE - 1));
    }

    pd = qatomic_rcu_read(lp);
    if (pd == NULL) {
        void *existing;

        if (!alloc) {
            return NULL;
        }

        pd = g_new0(PageDesc, V_L2_SIZE);
        for (int i = 0; i < V_L2_SIZE; i++) {
            qemu_spin_init(&pd[i].lock);
        }

        existing = qatomic_cmpxchg(lp, NULL, pd);
        if (unlikely(existing)) {
            for (int i = 0; i < V_L2_SIZE; i++) {
                qemu_spin_destroy(&pd[i].lock);
            }
            g_free(pd);
            pd = existing;
        }
    }

    return pd + (index & (V_L2_SIZE - 1));
}

static inline PageDesc *page_find(tb_page_addr_t index)
{
    return page_find_alloc(index, false);
}

/**
 * struct page_entry - page descriptor entry
 * @pd:     pointer to the &struct PageDesc of the page this entry represents
 * @index:  page index of the page
 * @locked: whether the page is locked
 *
 * This struct helps us keep track of the locked state of a page, without
 * bloating &struct PageDesc.
 *
 * A page lock protects accesses to all fields of &struct PageDesc.
 *
 * See also: &struct page_collection.
 */
struct page_entry {
    PageDesc *pd;
    tb_page_addr_t index;
    bool locked;
};

/**
 * struct page_collection - tracks a set of pages (i.e. &struct page_entry's)
 * @tree:   Binary search tree (BST) of the pages, with key == page index
 * @max:    Pointer to the page in @tree with the highest page index
 *
 * To avoid deadlock we lock pages in ascending order of page index.
 * When operating on a set of pages, we need to keep track of them so that
 * we can lock them in order and also unlock them later. For this we collect
 * pages (i.e. &struct page_entry's) in a binary search @tree. Given that the
 * @tree implementation we use does not provide an O(1) operation to obtain the
 * highest-ranked element, we use @max to keep track of the inserted page
 * with the highest index. This is valuable because if a page is not in
 * the tree and its index is higher than @max's, then we can lock it
 * without breaking the locking order rule.
 *
 * Note on naming: 'struct page_set' would be shorter, but we already have a few
 * page_set_*() helpers, so page_collection is used instead to avoid confusion.
 *
 * See also: page_collection_lock().
 */
struct page_collection {
    QTree *tree;
    struct page_entry *max;
};

typedef int PageForEachNext;
#define PAGE_FOR_EACH_TB(start, last, pagedesc, tb, n) \
    TB_FOR_EACH_TAGGED((pagedesc)->first_tb, tb, n, page_next)

#ifdef CONFIG_DEBUG_TCG

static __thread GHashTable *ht_pages_locked_debug;

static void ht_pages_locked_debug_init(void)
{
    if (ht_pages_locked_debug) {
        return;
    }
    ht_pages_locked_debug = g_hash_table_new(NULL, NULL);
}

static bool page_is_locked(const PageDesc *pd)
{
    PageDesc *found;

    ht_pages_locked_debug_init();
    found = g_hash_table_lookup(ht_pages_locked_debug, pd);
    return !!found;
}

static void page_lock__debug(PageDesc *pd)
{
    ht_pages_locked_debug_init();
    g_assert(!page_is_locked(pd));
    g_hash_table_insert(ht_pages_locked_debug, pd, pd);
}

static void page_unlock__debug(const PageDesc *pd)
{
    bool removed;

    ht_pages_locked_debug_init();
    g_assert(page_is_locked(pd));
    removed = g_hash_table_remove(ht_pages_locked_debug, pd);
    g_assert(removed);
}

static void do_assert_page_locked(const PageDesc *pd,
                                  const char *file, int line)
{
    if (unlikely(!page_is_locked(pd))) {
        error_report("assert_page_lock: PageDesc %p not locked @ %s:%d",
                     pd, file, line);
        abort();
    }
}
#define assert_page_locked(pd) do_assert_page_locked(pd, __FILE__, __LINE__)

void assert_no_pages_locked(void)
{
    ht_pages_locked_debug_init();
    g_assert(g_hash_table_size(ht_pages_locked_debug) == 0);
}

#else /* !CONFIG_DEBUG_TCG */

static inline void page_lock__debug(const PageDesc *pd) { }
static inline void page_unlock__debug(const PageDesc *pd) { }
static inline void assert_page_locked(const PageDesc *pd) { }

#endif /* CONFIG_DEBUG_TCG */

static void page_lock(PageDesc *pd)
{
    page_lock__debug(pd);
    qemu_spin_lock(&pd->lock);
}

/* Like qemu_spin_trylock, returns false on success */
static bool page_trylock(PageDesc *pd)
{
    bool busy = qemu_spin_trylock(&pd->lock);
    if (!busy) {
        page_lock__debug(pd);
    }
    return busy;
}

static void page_unlock(PageDesc *pd)
{
    qemu_spin_unlock(&pd->lock);
    page_unlock__debug(pd);
}

void tb_lock_page0(tb_page_addr_t paddr)
{
    page_lock(page_find_alloc(paddr >> TARGET_PAGE_BITS, true));
}

void tb_lock_page1(tb_page_addr_t paddr0, tb_page_addr_t paddr1)
{
    tb_page_addr_t pindex0 = paddr0 >> TARGET_PAGE_BITS;
    tb_page_addr_t pindex1 = paddr1 >> TARGET_PAGE_BITS;
    PageDesc *pd0, *pd1;

    if (pindex0 == pindex1) {
        /* Identical pages, and the first page is already locked. */
        return;
    }

    pd1 = page_find_alloc(pindex1, true);
    if (pindex0 < pindex1) {
        /* Correct locking order, we may block. */
        page_lock(pd1);
        return;
    }

    /* Incorrect locking order, we cannot block lest we deadlock. */
    if (!page_trylock(pd1)) {
        return;
    }

    /*
     * Drop the lock on page0 and get both page locks in the right order.
     * Restart translation via longjmp.
     */
    pd0 = page_find_alloc(pindex0, false);
    page_unlock(pd0);
    page_lock(pd1);
    page_lock(pd0);
    siglongjmp(tcg_ctx->jmp_trans, -3);
}

void tb_unlock_page1(tb_page_addr_t paddr0, tb_page_addr_t paddr1)
{
    tb_page_addr_t pindex0 = paddr0 >> TARGET_PAGE_BITS;
    tb_page_addr_t pindex1 = paddr1 >> TARGET_PAGE_BITS;

    if (pindex0 != pindex1) {
        page_unlock(page_find_alloc(pindex1, false));
    }
}

static void tb_lock_pages(TranslationBlock *tb)
{
    tb_page_addr_t paddr0 = tb_page_addr0(tb);
    tb_page_addr_t paddr1 = tb_page_addr1(tb);
    tb_page_addr_t pindex0 = paddr0 >> TARGET_PAGE_BITS;
    tb_page_addr_t pindex1 = paddr1 >> TARGET_PAGE_BITS;

    if (unlikely(paddr0 == -1)) {
        return;
    }
    if (unlikely(paddr1 != -1) && pindex0 != pindex1) {
        if (pindex0 < pindex1) {
            page_lock(page_find_alloc(pindex0, true));
            page_lock(page_find_alloc(pindex1, true));
            return;
        }
        page_lock(page_find_alloc(pindex1, true));
    }
    page_lock(page_find_alloc(pindex0, true));
}

void tb_unlock_pages(TranslationBlock *tb)
{
    tb_page_addr_t paddr0 = tb_page_addr0(tb);
    tb_page_addr_t paddr1 = tb_page_addr1(tb);
    tb_page_addr_t pindex0 = paddr0 >> TARGET_PAGE_BITS;
    tb_page_addr_t pindex1 = paddr1 >> TARGET_PAGE_BITS;

    if (unlikely(paddr0 == -1)) {
        return;
    }
    if (unlikely(paddr1 != -1) && pindex0 != pindex1) {
        page_unlock(page_find_alloc(pindex1, false));
    }
    page_unlock(page_find_alloc(pindex0, false));
}

static inline struct page_entry *
page_entry_new(PageDesc *pd, tb_page_addr_t index)
{
    struct page_entry *pe = g_malloc(sizeof(*pe));

    pe->index = index;
    pe->pd = pd;
    pe->locked = false;
    return pe;
}

static void page_entry_destroy(gpointer p)
{
    struct page_entry *pe = p;

    g_assert(pe->locked);
    page_unlock(pe->pd);
    g_free(pe);
}

/* returns false on success */
static bool page_entry_trylock(struct page_entry *pe)
{
    bool busy = page_trylock(pe->pd);
    if (!busy) {
        g_assert(!pe->locked);
        pe->locked = true;
    }
    return busy;
}

static void do_page_entry_lock(struct page_entry *pe)
{
    page_lock(pe->pd);
    g_assert(!pe->locked);
    pe->locked = true;
}

static gboolean page_entry_lock(gpointer key, gpointer value, gpointer data)
{
    struct page_entry *pe = value;

    do_page_entry_lock(pe);
    return FALSE;
}

static gboolean page_entry_unlock(gpointer key, gpointer value, gpointer data)
{
    struct page_entry *pe = value;

    if (pe->locked) {
        pe->locked = false;
        page_unlock(pe->pd);
    }
    return FALSE;
}

/*
 * Trylock a page, and if successful, add the page to a collection.
 * Returns true ("busy") if the page could not be locked; false otherwise.
 */
static bool page_trylock_add(struct page_collection *set, tb_page_addr_t addr)
{
    tb_page_addr_t index = addr >> TARGET_PAGE_BITS;
    struct page_entry *pe;
    PageDesc *pd;

    pe = q_tree_lookup(set->tree, &index);
    if (pe) {
        return false;
    }

    pd = page_find(index);
    if (pd == NULL) {
        return false;
    }

    pe = page_entry_new(pd, index);
    q_tree_insert(set->tree, &pe->index, pe);

    /*
     * If this is either (1) the first insertion or (2) a page whose index
     * is higher than any other so far, just lock the page and move on.
     */
    if (set->max == NULL || pe->index > set->max->index) {
        set->max = pe;
        do_page_entry_lock(pe);
        return false;
    }
    /*
     * Try to acquire out-of-order lock; if busy, return busy so that we acquire
     * locks in order.
     */
    return page_entry_trylock(pe);
}

static gint tb_page_addr_cmp(gconstpointer ap, gconstpointer bp, gpointer udata)
{
    tb_page_addr_t a = *(const tb_page_addr_t *)ap;
    tb_page_addr_t b = *(const tb_page_addr_t *)bp;

    if (a == b) {
        return 0;
    } else if (a < b) {
        return -1;
    }
    return 1;
}

/*
 * Lock a range of pages ([@start,@last]) as well as the pages of all
 * intersecting TBs.
 * Locking order: acquire locks in ascending order of page index.
 */
static struct page_collection *page_collection_lock(tb_page_addr_t start,
                                                    tb_page_addr_t last)
{
    struct page_collection *set = g_malloc(sizeof(*set));
    tb_page_addr_t index;
    PageDesc *pd;

    start >>= TARGET_PAGE_BITS;
    last >>= TARGET_PAGE_BITS;
    g_assert(start <= last);

    set->tree = q_tree_new_full(tb_page_addr_cmp, NULL, NULL,
                                page_entry_destroy);
    set->max = NULL;
    assert_no_pages_locked();

 retry:
    q_tree_foreach(set->tree, page_entry_lock, NULL);

    for (index = start; index <= last; index++) {
        TranslationBlock *tb;
        PageForEachNext n;

        pd = page_find(index);
        if (pd == NULL) {
            continue;
        }
        if (page_trylock_add(set, index << TARGET_PAGE_BITS)) {
            q_tree_foreach(set->tree, page_entry_unlock, NULL);
            goto retry;
        }
        assert_page_locked(pd);
        PAGE_FOR_EACH_TB(unused, unused, pd, tb, n) {
            if (page_trylock_add(set, tb_page_addr0(tb)) ||
                (tb_page_addr1(tb) != -1 &&
                 page_trylock_add(set, tb_page_addr1(tb)))) {
                /* drop all locks, and reacquire in order */
                q_tree_foreach(set->tree, page_entry_unlock, NULL);
                goto retry;
            }
        }
    }
    return set;
}

static void page_collection_unlock(struct page_collection *set)
{
    /* entries are unlocked and freed via page_entry_destroy */
    q_tree_destroy(set->tree);
    g_free(set);
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */
static void tb_remove_all_1(int level, void **lp)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            page_lock(&pd[i]);
            pd[i].first_tb = (uintptr_t)NULL;
            page_unlock(&pd[i]);
        }
    } else {
        void **pp = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            tb_remove_all_1(level - 1, pp + i);
        }
    }
}

static void tb_remove_all(void)
{
    int i, l1_sz = v_l1_size;

    for (i = 0; i < l1_sz; i++) {
        tb_remove_all_1(v_l2_levels, l1_map + i);
    }
}

/*
 * Add the tb in the target page and protect it if necessary.
 * Called with @p->lock held.
 */
static void tb_page_add(PageDesc *p, TranslationBlock *tb, unsigned int n)
{
    bool page_already_protected;

    assert_page_locked(p);

    tb->page_next[n] = p->first_tb;
    page_already_protected = p->first_tb != 0;
    p->first_tb = (uintptr_t)tb | n;

    /*
     * If some code is already present, then the pages are already
     * protected. So we handle the case where only the first TB is
     * allocated in a physical page.
     */
    if (!page_already_protected) {
        tlb_protect_code(tb->page_addr[n] & TARGET_PAGE_MASK);
    }
}

/* @defer: user mode only. */
static void tb_record(TranslationBlock *tb, bool defer)
{
    tb_page_addr_t paddr0 = tb_page_addr0(tb);
    tb_page_addr_t paddr1 = tb_page_addr1(tb);
    tb_page_addr_t pindex0 = paddr0 >> TARGET_PAGE_BITS;
    tb_page_addr_t pindex1 = paddr1 >> TARGET_PAGE_BITS;

    assert(paddr0 != -1);
    if (unlikely(paddr1 != -1) && pindex0 != pindex1) {
        tb_page_add(page_find_alloc(pindex1, false), tb, 1);
    }
    tb_page_add(page_find_alloc(pindex0, false), tb, 0);
}

static void tb_page_remove(PageDesc *pd, TranslationBlock *tb)
{
    TranslationBlock *tb1;
    uintptr_t *pprev;
    PageForEachNext n1;

    assert_page_locked(pd);
    pprev = &pd->first_tb;
    PAGE_FOR_EACH_TB(unused, unused, pd, tb1, n1) {
        if (tb1 == tb) {
            *pprev = tb1->page_next[n1];
            return;
        }
        pprev = &tb1->page_next[n1];
    }
    g_assert_not_reached();
}

static void tb_remove(TranslationBlock *tb)
{
    tb_page_addr_t paddr0 = tb_page_addr0(tb);
    tb_page_addr_t paddr1 = tb_page_addr1(tb);
    tb_page_addr_t pindex0 = paddr0 >> TARGET_PAGE_BITS;
    tb_page_addr_t pindex1 = paddr1 >> TARGET_PAGE_BITS;

    assert(paddr0 != -1);
    if (unlikely(paddr1 != -1) && pindex0 != pindex1) {
        tb_page_remove(page_find_alloc(pindex1, false), tb);
    }
    tb_page_remove(page_find_alloc(pindex0, false), tb);
}
#endif /* CONFIG_USER_ONLY */

/*
 * Flush all the translation blocks.
 * Must be called from a context in which no cpus are running,
 * e.g. start_exclusive() or vm_stop().
 */
void tb_flush__exclusive_or_serial(void)
{
    CPUState *cpu;

    trace_tb_flush();
    assert(tcg_enabled());
    /* Note that cpu_in_serial_context checks cpu_in_exclusive_context. */
    assert(!runstate_is_running() ||
           (current_cpu && cpu_in_serial_context(current_cpu)));

    CPU_FOREACH(cpu) {
        tcg_clear_jmp_cache(cpu);
    }

    qht_reset_size(&tb_ctx.htable, CODE_GEN_HTABLE_SIZE);
    tb_remove_all();

    tcg_region_reset_all();
    /* XXX: flush processor icache at this point if cache flush is expensive */
    qatomic_inc(&tb_ctx.tb_flush_count);
    qemu_plugin_flush_cb();
}

static void do_tb_flush(CPUState *cpu, run_on_cpu_data tb_flush_count)
{
    /* If it is already been done on request of another CPU, just retry. */
    if (tb_ctx.tb_flush_count == tb_flush_count.host_int) {
        tb_flush__exclusive_or_serial();
    }
}

void queue_tb_flush(CPUState *cs)
{
    if (tcg_enabled()) {
        unsigned tb_flush_count = qatomic_read(&tb_ctx.tb_flush_count);
        async_safe_run_on_cpu(cs, do_tb_flush,
                              RUN_ON_CPU_HOST_INT(tb_flush_count));
    }
}

/* remove @orig from its @n_orig-th jump list */
static inline void tb_remove_from_jmp_list(TranslationBlock *orig, int n_orig)
{
    uintptr_t ptr, ptr_locked;
    TranslationBlock *dest;
    TranslationBlock *tb;
    uintptr_t *pprev;
    int n;

    /* mark the LSB of jmp_dest[] so that no further jumps can be inserted */
    ptr = qatomic_or_fetch(&orig->jmp[n_orig].dest, 1);
    dest = (TranslationBlock *)(ptr & ~1);
    if (dest == NULL) {
        return;
    }

    qemu_spin_lock(&dest->jmp_lock);
    /*
     * While acquiring the lock, the jump might have been removed if the
     * destination TB was invalidated; check again.
     */
    ptr_locked = qatomic_read(&orig->jmp[n_orig].dest);
    if (ptr_locked != ptr) {
        qemu_spin_unlock(&dest->jmp_lock);
        /*
         * The only possibility is that the jump was unlinked via
         * tb_jump_unlink(dest). Seeing here another destination would be a bug,
         * because we set the LSB above.
         */
        g_assert(ptr_locked == 1 && dest->cflags & CF_INVALID);
        return;
    }
    /*
     * We first acquired the lock, and since the destination pointer matches,
     * we know for sure that @orig is in the jmp list.
     */
    if (dest == orig) {
        /*
         * In the case of a TB that links to itself, removing the entry
         * from the list means that it won't be present later during
         * tb_jmp_unlink -- unlink now.
         */
        tb_reset_jump(orig, n_orig);
    }
    pprev = &dest->jmp_list_head;
    TB_FOR_EACH_JMP(dest, tb, n) {
        if (tb == orig && n == n_orig) {
            *pprev = tb->jmp[n].list_next;
            /* no need to set orig->jmp[n].dest; setting the LSB was enough */
            qemu_spin_unlock(&dest->jmp_lock);
            return;
        }
        pprev = &tb->jmp[n].list_next;
    }
    g_assert_not_reached();
}

/*
 * Reset the jump entry 'n' of a TB so that it is not chained to another TB.
 */
void tb_reset_jump(TranslationBlock *tb, int n)
{
    uintptr_t addr = (uintptr_t)(tb->tc.ptr + tb->jmp[n].reset_offset);
    tb_set_jmp_target(tb, n, addr);
}

/* remove any jumps to the TB */
static inline void tb_jmp_unlink(TranslationBlock *dest)
{
    TranslationBlock *tb;
    int n;

    qemu_spin_lock(&dest->jmp_lock);

    TB_FOR_EACH_JMP(dest, tb, n) {
        tb_reset_jump(tb, n);
        qatomic_and(&tb->jmp[n].dest, (uintptr_t)NULL | 1);
        /* No need to clear the list entry; setting the dest ptr is enough */
    }
    dest->jmp_list_head = (uintptr_t)NULL;

    qemu_spin_unlock(&dest->jmp_lock);
}

static void tb_jmp_cache_inval_tb(TranslationBlock *tb)
{
    CPUState *cpu;
    uint32_t h;

    /*
     * A CF_PCREL TB may be at any virtual address, so its entries can't be
     * found.  They can stay: CF_INVALID is set, and every jump-cache lookup
     * compares the TB's cflags with the current ones, so they never match
     * again; the TB's memory is reused only after tb_flush, which flushes
     * every jump cache.
     */
    if (tb_cflags(tb) & CF_PCREL) {
        return;
    }

    h = tb_jmp_cache_hash_func(tb->pc);
    CPU_FOREACH(cpu) {
        CPUJumpCache *jc = cpu->tb_jmp_cache;

        if (qatomic_read(&jc->array[h].tb) == tb) {
            qatomic_set(&jc->array[h].tb, NULL);
        }
    }
}

/*
 * In user-mode, call with mmap_lock held.
 * In !user-mode, if @rm_from_page_list is set, call with the TB's pages'
 * locks held.
 */
static void do_tb_phys_invalidate(TranslationBlock *tb, bool rm_from_page_list)
{
    uint32_t h;
    tb_page_addr_t phys_pc;
    uint32_t orig_cflags = tb_cflags(tb);

    assert_memory_lock();
    qemu_thread_jit_write();

    /* make sure no further incoming jumps will be chained to this TB */
    qemu_spin_lock(&tb->jmp_lock);
    qatomic_set(&tb->cflags, tb->cflags | CF_INVALID);
    qemu_spin_unlock(&tb->jmp_lock);
    /* Testing: an invalidated TB stays found for unwinding. */
    if (unlikely(tcg_tb_lookup_verify)) {
        g_assert(tcg_tb_lookup((uintptr_t)tb->tc.ptr) == tb);
    }

    /*
     * A vCPU may be running a loop inside this TB, which unlinking its
     * jumps would not end: make every vCPU leave its current TB.
     */
    if (tb->loops) {
        CPUState *cpu;

        WITH_RCU_READ_LOCK_GUARD() {
            CPU_FOREACH(cpu) {
                cpu_exit(cpu);
            }
        }
    }

    /* remove the TB from the hash list */
    phys_pc = tb_page_addr0(tb);
    h = tb_hash_func(phys_pc, (orig_cflags & CF_PCREL ? 0 : tb->pc),
                     tb->flags, tb->cs_base, orig_cflags);
    if (qht_remove(&tb_ctx.htable, tb, h)) {

        /* remove the TB from the page list */
        if (rm_from_page_list) {
            tb_remove(tb);
        }

        /* remove the TB from the hash list */
        tb_jmp_cache_inval_tb(tb);

        /* suppress this TB from its jump lists */
        for (int n = 0; n < tb->nb_slots; n++) {
            tb_remove_from_jmp_list(tb, n);
        }

        /* suppress any remaining jumps to this TB */
        tb_jmp_unlink(tb);

        /*
         * A host return may still enter a TB that pushed its return
         * landing (tcg_gen_push_ret): its own jumps lead to its exits.
         */
        if (tb->jmp_call) {
            for (int n = 0; n < tb->nb_slots; n++) {
                if (tb->jmp[n].reset_offset != TB_JMP_OFFSET_INVALID) {
                    tb_reset_jump(tb, n);
                }
            }
        }

        qatomic_set(&tb_ctx.tb_phys_invalidate_count,
                    tb_ctx.tb_phys_invalidate_count + 1);
    }

    qemu_thread_jit_execute();
}

/*
 * Invalidate one TB.
 * Called with mmap_lock held in user-mode.
 */
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr)
{
    if (page_addr == -1 && tb_page_addr0(tb) != -1) {
        tb_lock_pages(tb);
        do_tb_phys_invalidate(tb, true);
        tb_unlock_pages(tb);
    } else {
        do_tb_phys_invalidate(tb, false);
    }
}

/*
 * Add a new TB and link it to the physical page tables.
 * Called with mmap_lock held for user-mode emulation.
 * With @defer_pages, user mode enters the TB in page tracking only when a
 * query meets its pages: for TBs that, like a persistent cache's, arrive
 * in numbers few queries will need.
 *
 * Returns a pointer @tb, or a pointer to an existing TB that matches @tb.
 * Note that in !user-mode, another thread might have already added a TB
 * for the same block of guest code that @tb corresponds to. In that case,
 * the caller should discard the original @tb, and use instead the returned TB.
 */
TranslationBlock *tb_link_page(TranslationBlock *tb, bool defer_pages)
{
    void *existing_tb = NULL;
    uint32_t h;

    assert_memory_lock();
    tcg_debug_assert(!(tb->cflags & CF_INVALID));

    tb_record(tb, defer_pages);
#ifdef CONFIG_USER_ONLY
    pt_shadow_add(tb);
#endif

    /* add in the hash table */
    h = tb_hash_func(tb_page_addr0(tb), (tb->cflags & CF_PCREL ? 0 : tb->pc),
                     tb->flags, tb->cs_base, tb->cflags);
    qht_insert(&tb_ctx.htable, tb, h, &existing_tb);

    /* remove TB from the page(s) if we couldn't insert it */
    if (unlikely(existing_tb)) {
        tb_remove(tb);
        tb_unlock_pages(tb);
        return existing_tb;
    }

    tb_unlock_pages(tb);
    return tb;
}

/*
 * Whether the code of @tb has bytes in [@start, @last], a range within
 * one page, counting its bytes as PAGE_FOR_EACH_TB's callers do.
 */
static bool tb_code_overlaps(const TranslationBlock *tb, tb_page_addr_t start,
                             tb_page_addr_t last)
{
    tb_page_addr_t p0 = tb_page_addr0(tb), p1 = tb_page_addr1(tb);
    tb_page_addr_t last0 = p0 + tb->size - 1;

    if (p0 == -1) {
        return false;
    }
    if (p0 <= last && MIN(last0, p0 | ~TARGET_PAGE_MASK) >= start) {
        return true;
    }
    return p1 != -1 && p1 <= last &&
           p1 + (last0 & ~TARGET_PAGE_MASK) >= start;
}

#ifdef CONFIG_USER_ONLY
/*
 * Invalidate all TBs which intersect with the target address range.
 * Called with mmap_lock held for user-mode emulation.
 * NOTE: this function must not be called while a TB is running.
 */
void tb_invalidate_phys_range(CPUState *cpu, tb_page_addr_t start,
                              tb_page_addr_t last)
{
    TranslationBlock *tb;
    PageForEachNext n;

    assert_memory_lock();

    translator_region_forget(start, last);
    PAGE_FOR_EACH_TB(start, last, unused, tb, n) {
        do_tb_phys_invalidate(tb, true);
    }
}

/*
 * Invalidate all TBs which intersect with the target address page @addr.
 * Called with mmap_lock held for user-mode emulation
 * NOTE: this function must not be called while a TB is running.
 */
static void tb_invalidate_phys_page(tb_page_addr_t addr)
{
    tb_page_addr_t start, last;

    start = addr & TARGET_PAGE_MASK;
    last = addr | ~TARGET_PAGE_MASK;
    tb_invalidate_phys_range(NULL, start, last);
}

/*
 * Called with mmap_lock held. If pc is not 0 then it indicates the
 * host PC of the faulting store instruction that caused this invalidate.
 * Returns true if the caller needs to abort execution of the current TB.
 */
bool tb_invalidate_phys_page_unwind(CPUState *cpu, tb_page_addr_t addr,
                                    uintptr_t pc)
{
    TranslationBlock *current_tb;
    bool current_tb_modified;
    TranslationBlock *tb;
    PageForEachNext n;
    tb_page_addr_t last;

    /*
     * Without precise smc semantics, or when outside of a TB,
     * we can skip to invalidate.
     */
    if (!pc || !cpu || !cpu->cc->tcg_ops->precise_smc) {
        tb_invalidate_phys_page(addr);
        return false;
    }

    assert_memory_lock();
    current_tb = tcg_tb_lookup(pc);

    last = addr | ~TARGET_PAGE_MASK;
    addr &= TARGET_PAGE_MASK;
    current_tb_modified = false;

    PAGE_FOR_EACH_TB(addr, last, unused, tb, n) {
        if (current_tb == tb &&
            (tb_cflags(current_tb) & CF_COUNT_MASK) != 1) {
            /*
             * If we are modifying the current TB, we must stop its
             * execution. We could be more precise by checking that
             * the modification is after the current PC, but it would
             * require a specialized function to partially restore
             * the CPU state.
             */
            current_tb_modified = true;
            cpu_restore_state_from_tb(cpu, current_tb, pc);
        }
        do_tb_phys_invalidate(tb, true);
    }
    /*
     * The current TB may be off the page's list already, invalidated
     * while it runs: a store of its own to its code must stop it all
     * the same.
     */
    if (!current_tb_modified && current_tb &&
        (tb_cflags(current_tb) & CF_COUNT_MASK) != 1 &&
        tb_code_overlaps(current_tb, addr, last)) {
        current_tb_modified = true;
        cpu_restore_state_from_tb(cpu, current_tb, pc);
    }

    if (current_tb_modified) {
        /* Force execution of one insn next time.  */
        cpu->cflags_next_tb = 1 | CF_NOIRQ | curr_cflags(cpu);
        return true;
    }
    return false;
}
#else
/*
 * @p must be non-NULL.
 * Call with all @pages locked.
 * (@cpu, @retaddr) may be (NULL, 0) outside of a cpu context,
 * in which case precise_smc need not be detected.
 */
static void
tb_invalidate_phys_page_range__locked(CPUState *cpu,
                                      struct page_collection *pages,
                                      PageDesc *p, tb_page_addr_t start,
                                      tb_page_addr_t last,
                                      uintptr_t retaddr)
{
    TranslationBlock *tb;
    PageForEachNext n;
    bool current_tb_modified = false;
    TranslationBlock *current_tb = NULL;

    /* Range may not cross a page. */
    tcg_debug_assert(((start ^ last) & TARGET_PAGE_MASK) == 0);

    if (retaddr && cpu && cpu->cc->tcg_ops->precise_smc) {
        current_tb = tcg_tb_lookup(retaddr);
    }

    /*
     * We remove all the TBs in the range [start, last].
     * XXX: see if in some cases it could be faster to invalidate all the code
     */
    PAGE_FOR_EACH_TB(start, last, p, tb, n) {
        tb_page_addr_t tb_start, tb_last;

        /* NOTE: this is subtle as a TB may span two physical pages */
        tb_start = tb_page_addr0(tb);
        tb_last = tb_start + tb->size - 1;
        if (n == 0) {
            tb_last = MIN(tb_last, tb_start | ~TARGET_PAGE_MASK);
        } else {
            tb_start = tb_page_addr1(tb);
            tb_last = tb_start + (tb_last & ~TARGET_PAGE_MASK);
        }
        if (!(tb_last < start || tb_start > last)) {
            if (unlikely(current_tb == tb) &&
                (tb_cflags(current_tb) & CF_COUNT_MASK) != 1) {
                /*
                 * If we are modifying the current TB, we must stop
                 * its execution. We could be more precise by checking
                 * that the modification is after the current PC, but it
                 * would require a specialized function to partially
                 * restore the CPU state.
                 */
                current_tb_modified = true;
                cpu_restore_state_from_tb(cpu, current_tb, retaddr);
            }
            do_tb_phys_invalidate(tb, true);
        }
    }
    /*
     * The current TB may be off the page's list already, invalidated
     * while it runs: a store of its own to its code must stop it all
     * the same.
     */
    if (!current_tb_modified && current_tb &&
        (tb_cflags(current_tb) & CF_COUNT_MASK) != 1 &&
        tb_code_overlaps(current_tb, start, last)) {
        current_tb_modified = true;
        cpu_restore_state_from_tb(cpu, current_tb, retaddr);
    }

    /* if no code remaining, no need to continue to use slow writes */
    if (!p->first_tb) {
        tlb_unprotect_code(start);
    }

    if (unlikely(current_tb_modified)) {
        page_collection_unlock(pages);
        /* Force execution of one insn next time.  */
        cpu->cflags_next_tb = 1 | CF_NOIRQ | curr_cflags(cpu);
        cpu_loop_exit_noexc(cpu);
    }
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;last]. NOTE: start and end may refer to *different* physical pages.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 */
void tb_invalidate_phys_range(CPUState *cpu, tb_page_addr_t start,
                              tb_page_addr_t last)
{
    struct page_collection *pages;
    tb_page_addr_t index, index_last;

    translator_region_forget(start, last);
    pages = page_collection_lock(start, last);

    index_last = last >> TARGET_PAGE_BITS;
    for (index = start >> TARGET_PAGE_BITS; index <= index_last; index++) {
        PageDesc *pd = page_find(index);
        tb_page_addr_t page_start, page_last;

        if (pd == NULL) {
            continue;
        }
        assert_page_locked(pd);
        page_start = index << TARGET_PAGE_BITS;
        page_last = page_start | ~TARGET_PAGE_MASK;
        page_last = MIN(page_last, last);
        tb_invalidate_phys_page_range__locked(cpu, pages, pd,
                                              page_start, page_last, 0);
    }
    page_collection_unlock(pages);
}

/*
 * len must be <= 8 and start must be a multiple of len.
 * Called via softmmu_template.h when code areas are written to with
 * iothread mutex not held.
 */
void tb_invalidate_phys_range_fast(CPUState *cpu, ram_addr_t start,
                                   unsigned len, uintptr_t ra)
{
    PageDesc *p = page_find(start >> TARGET_PAGE_BITS);

    if (p) {
        ram_addr_t last = start + len - 1;
        struct page_collection *pages;

        translator_region_forget(start, last);
        pages = page_collection_lock(start, last);

        tb_invalidate_phys_page_range__locked(cpu, pages, p,
                                              start, last, ra);
        page_collection_unlock(pages);
    }
}

#endif /* CONFIG_USER_ONLY */

/*
 * In user mode, fault on the first page before touching the second: the
 * helpers below may read or write the page-crossing access's second page
 * first.  (System mode's softmmu lookup already goes in order.)
 */
static void tso_cross_probe(CPUArchState *env, uint64_t addr, MemOpIdx oi,
                            MMUAccessType access_type, uintptr_t retaddr)
{
#ifdef CONFIG_USER_ONLY
    int size = memop_size(get_memop(oi));

    if ((addr & ~TARGET_PAGE_MASK) + size > TARGET_PAGE_SIZE) {
        probe_access(env, addr, 1, access_type, get_mmuidx(oi), retaddr);
    }
#endif
}

/*
 * An MO_ACQ_REL access of guest insn @site crossed a 16-byte boundary.
 * Once the insn is promoted, invalidate the TB at @retaddr and leave it
 * before the access, so that the insn is retranslated with
 * MO_ACQ_REL_CROSS (see tcg_gen_ldst_order) and executed again.  The TB
 * must not go on: invalidation takes it off its pages' TB lists, and the
 * precise SMC check finds the current TB among those, so a store of the
 * TB's own to code further on in it would not stop it.
 */
static void tso_cross_note(CPUState *cpu, uint64_t addr, MemOpIdx oi,
                           uintptr_t retaddr, uint64_t site)
{
    TranslationBlock *tb;

    /* In system mode, a TLB miss comes here too. */
    if ((addr & 15) + memop_size(get_memop(oi)) <= 16) {
        return;
    }
    /* The site table is a GHashTable, which uses host floating point. */
    TCG_HOST_FP_SUSPEND_GUARD(cpu);
    if (!tcg_tso_cross_count(site)) {
        return;
    }
    tb = tcg_tb_lookup(retaddr);
    if (tb && !(tb_cflags(tb) & CF_INVALID)) {
        mmap_lock();
        tb_phys_invalidate(tb, -1);
        mmap_unlock();
        cpu_restore_state_from_tb(cpu, tb, retaddr);
        cpu_loop_exit_noexc(cpu);
    }
}

tcg_target_ulong helper_tso_cross_ld(CPUArchState *env, uint64_t addr,
                                     MemOpIdx oi, uintptr_t retaddr,
                                     uint64_t site)
{
    tso_cross_note(env_cpu(env), addr, oi, retaddr, site);
    tso_cross_probe(env, addr, oi, MMU_DATA_LOAD, retaddr);
    switch (get_memop(oi) & MO_SIZE) {
    case MO_16:
        return helper_lduw_mmu(env, addr, oi, retaddr);
    case MO_32:
        return helper_ldul_mmu(env, addr, oi, retaddr);
    case MO_64:
        return helper_ldq_mmu(env, addr, oi, retaddr);
    default:
        g_assert_not_reached();
    }
}

uintptr_t helper_tso_cross_thunk(CPUArchState *env, uint64_t *regs,
                                 const uint32_t *desc)
{
    uintptr_t retaddr = (uintptr_t)desc + (int32_t)desc[0];
    MemOpIdx oi = desc[1];
    uint64_t site = desc[2] | (uint64_t)desc[3] << 32;
    uint32_t flags = desc[4];
    uint64_t addr = regs[flags & 31];
    unsigned data = (flags >> 5) & 31;

    if (flags & TSO_THUNK_ADDR32) {
        addr = (uint32_t)addr;
    }
    if (flags & TSO_THUNK_IS_LD) {
        MemOp mop = get_memop(oi);
        uint64_t val = helper_tso_cross_ld(env, addr, oi, retaddr, site);

        /* As tcg_out_ld_helper_ret extends it. */
        if (mop & MO_SIGN) {
            val = sextract64(val, 0, memop_size(mop) * 8);
        }
        if (!(flags & TSO_THUNK_DATA64)) {
            val = (uint32_t)val;
        }
        regs[data] = val;
    } else {
        helper_tso_cross_st(env, addr, regs[data], oi, retaddr, site);
    }
    if (flags & TSO_THUNK_DIRECT) {
        return retaddr;
    }
    return (uintptr_t)(desc + TSO_THUNK_DESC_WORDS);
}

void helper_tso_cross_st(CPUArchState *env, uint64_t addr, uint64_t val,
                         MemOpIdx oi, uintptr_t retaddr, uint64_t site)
{
    tso_cross_note(env_cpu(env), addr, oi, retaddr, site);
    tso_cross_probe(env, addr, oi, MMU_DATA_STORE, retaddr);
    switch (get_memop(oi) & MO_SIZE) {
    case MO_16:
        helper_stw_mmu(env, addr, val, oi, retaddr);
        break;
    case MO_32:
        helper_stl_mmu(env, addr, val, oi, retaddr);
        break;
    case MO_64:
        helper_stq_mmu(env, addr, val, oi, retaddr);
        break;
    default:
        g_assert_not_reached();
    }
}
