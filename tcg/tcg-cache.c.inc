/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Translation artifacts (tcg-cache.h): capture a TB as a self-contained
 * record, and install a record again at another place in the code buffer.
 * Included at the end of tcg.c, for the layout and the back end's
 * decode, zero and apply (TCG_TARGET_HAS_CACHE).
 */

int tcg_cache_mode;
static bool tcg_cache_verify_on;
unsigned tcg_cache_skew;
bool tcg_cache_stats_at_exit;
bool tcg_cache_debug;
bool tcg_cache_costs;
bool tcg_cache_validate_always;
int tcg_cache_test_unwind_damage;
unsigned tcg_cache_test_capture_damage;
unsigned tcg_cache_test_capture_damage_after;
unsigned tcg_cache_test_firstuse_pause_ms;
bool tcg_cache_timing;
bool tcg_cache_no_write;
unsigned tcg_cache_test_reject;
bool tcg_cache_test_reget_fail;

/*
 * With XTCG_CACHE_COSTS, the time since *@t added to *@acc, and *@t moved
 * on.  Off by default: where reading the clock is slow (about 80 ns on
 * Windows on Arm), a lookup's dozens of readings would cost more than its
 * parts.
 */
unsigned tcg_cache_test_img_shift;

void tcg_cache_part(uint64_t *acc, int64_t *t)
{
    if (tcg_cache_costs) {
        int64_t now = get_clock();

        *acc += now - *t;
        *t = now;
    }
}
unsigned tcg_cache_flush_every;
size_t tcg_cache_max = 256 * MiB;
bool tcg_cache_inj_promote;
const TCGCacheHost *tcg_cache_host;
bool tcg_cache_trace;

static void tcg_cache_out_stderr(const char *line)
{
    fputs(line, stderr);
}

void (*tcg_cache_out)(const char *line) = tcg_cache_out_stderr;
TCGCacheStats tcg_cache_stats;

const char *const tcg_cache_x_names[TCG_CACHE_X_MAX] = {
    [TCG_CACHE_X_NONE] = "none",
    [TCG_CACHE_X_SMC] = "smc",
    [TCG_CACHE_X_REGION] = "region",
    [TCG_CACHE_X_PROMOTED] = "promoted",
    [TCG_CACHE_X_HOSTPTR] = "hostptr",
    [TCG_CACHE_X_PLUGIN] = "plugin",
    [TCG_CACHE_X_TORN] = "torn",
    [TCG_CACHE_X_SPAN] = "span",
    [TCG_CACHE_X_FAKE] = "fake",
    [TCG_CACHE_X_UNKNOWN_REF] = "unknown-ref",
    [TCG_CACHE_X_RAW_ADRP] = "raw-adrp",
    [TCG_CACHE_X_ORR_PTR] = "orr-ptr",
    [TCG_CACHE_X_POOL_MIX] = "pool-mix",
    [TCG_CACHE_X_UNSUPPORTED] = "unsupported",
    [TCG_CACHE_X_TOO_MANY] = "too-many",
    [TCG_CACHE_X_PROV] = "prov",
    [TCG_CACHE_X_LAZY] = "lazy",
    [TCG_CACHE_X_VERIFY] = "verify",
    [TCG_CACHE_X_INVALID] = "invalid",
};

/*
 * XTCG_CACHE=capture|stress|on (development): record and check every
 * translation, or also install each from its artifact, or keep eligible
 * artifacts and install from them before translating.  XTCG_CACHE_SKEW=n
 * moves each install by up to n 16-byte steps in each part;
 * XTCG_CACHE_FLUSH=n flushes the code buffer every n translations;
 * XTCG_CACHE_MAX=n bounds the store at n MiB; XTCG_CACHE_INJPROMOTE
 * promotes an install's first acquire/release site after its check.
 */
static void tcg_cache_init(void)
{
    const char *m = getenv("XTCG_CACHE");
    const char *k = getenv("XTCG_CACHE_SKEW");

    if (m && !strcmp(m, "capture")) {
        tcg_cache_mode = TCG_CACHE_CAPTURE;
    } else if (m && !strcmp(m, "stress")) {
        tcg_cache_mode = TCG_CACHE_STRESS;
    } else if (m && !strcmp(m, "on")) {
        tcg_cache_mode = TCG_CACHE_ON;
    }
    tcg_cache_verify_on = tcg_cache_mode != TCG_CACHE_OFF
                          && !getenv("XTCG_CACHE_NOVERIFY");
    if (k) {
        tcg_cache_skew = atoi(k);
    }
    if (getenv("XTCG_CACHE_DEBUG")) {
        tcg_cache_debug = true;
    }
    m = getenv("XTCG_CACHE_VALIDATE");
    tcg_cache_validate_always = m && !strcmp(m, "always");
    m = getenv("XTCG_CACHE_TEST_UNWIND_DAMAGE");
    if (m && atoi(m) > 0 && atoi(m) < TCG_CACHE_DAMAGE_MAX) {
        tcg_cache_test_unwind_damage = atoi(m);
    }
    m = getenv("XTCG_CACHE_TEST_CAPTURE_DAMAGE");
    if (m && atoi(m) > 0) {
        tcg_cache_test_capture_damage = atoi(m);
    }
    m = getenv("XTCG_CACHE_TEST_CAPTURE_DAMAGE_AFTER");
    if (m && atoi(m) > 0) {
        tcg_cache_test_capture_damage_after = atoi(m);
    }
    m = getenv("XTCG_CACHE_TEST_FIRSTUSE_PAUSE_MS");
    if (m && atoi(m) > 0) {
        tcg_cache_test_firstuse_pause_ms = atoi(m);
    }
    tcg_cache_costs = getenv("XTCG_CACHE_COSTS");
    tcg_cache_pages = getenv("XTCG_CACHE_PAGES");
    if (getenv("XTCG_CACHE_TEST_IMG_SHIFT")) {
        const char *v = getenv("XTCG_CACHE_TEST_IMG_SHIFT");

        int shift = atoi(v);

        tcg_cache_test_img_shift = shift > 0 && shift < 64 ? shift : 0;
    }
    if (tcg_cache_costs || getenv("XTCG_CACHE_STATS")) {
        tcg_cache_timing = true;
    }
    if (getenv("XTCG_CACHE_NOWRITE")) {
        tcg_cache_no_write = true;
    }
    if (getenv("XTCG_CACHE_TEST_REJECT")) {
        tcg_cache_test_reject = atoi(getenv("XTCG_CACHE_TEST_REJECT"));
    }
    tcg_cache_test_reget_fail = getenv("XTCG_CACHE_TEST_REGETFAIL");
    k = getenv("XTCG_CACHE_FLUSH");
    if (k) {
        tcg_cache_flush_every = atoi(k);
    }
    k = getenv("XTCG_CACHE_MAX");
    if (k) {
        tcg_cache_max = (size_t)atoi(k) * MiB;
    }
    if (getenv("XTCG_CACHE_INJPROMOTE")) {
        tcg_cache_inj_promote = true;
    }
    if (getenv("XTCG_CACHE_TRACE")) {
        tcg_cache_trace = true;
    }
}

/* Front end. */


void tcg_cache_tb_start(TCGContext *s, vaddr pc_first, unsigned page_bits)
{
    uint32_t span = 2u << page_bits;

    if (!s->cap_on) {
        return;
    }
    s->cap_page = pc_first & ~(((vaddr)1 << page_bits) - 1);
    if (span > s->cap_span) {
        s->cap_bytes = g_realloc(s->cap_bytes, span);
        s->cap_span = span;
    }
    if (!s->cap_ext) {
        s->cap_ext = g_new(TCGCacheArtExt, TCG_CACHE_MAX_EXT);
    }
}

void tcg_cache_exclude(TCGContext *s, unsigned reason)
{
    if (s->cap_on && !s->cap_excl) {
        s->cap_excl = reason;
    }
}

/*
 * The bytes the translation read at @pc: kept by their offset in the two
 * pages; a byte read again must read the same.
 */
void tcg_cache_read(TCGContext *s, vaddr pc, const void *p, size_t len)
{
    uint32_t off, end;
    int i, j;

    if (!s->cap_on || s->cap_excl || !len) {
        return;
    }
    if (pc < s->cap_page || pc - s->cap_page + len > s->cap_span) {
        tcg_cache_exclude(s, TCG_CACHE_X_SPAN);
        return;
    }
    off = pc - s->cap_page;
    end = off + len;
    for (i = 0; i < s->cap_next; i++) {
        uint32_t lo = MAX(off, s->cap_ext[i].off);
        uint32_t hi = MIN(end, s->cap_ext[i].off + s->cap_ext[i].len);

        if (lo < hi && memcmp(s->cap_bytes + lo,
                              (const uint8_t *)p + (lo - off), hi - lo)) {
            tcg_cache_exclude(s, TCG_CACHE_X_TORN);
            return;
        }
    }
    memcpy(s->cap_bytes + off, p, len);

    /* Merge [off, end) into the sorted, disjoint extents. */
    for (i = 0; i < s->cap_next && s->cap_ext[i].off + s->cap_ext[i].len
                                   < off; i++) {
        continue;
    }
    for (j = i; j < s->cap_next && s->cap_ext[j].off <= end; j++) {
        off = MIN(off, s->cap_ext[j].off);
        end = MAX(end, s->cap_ext[j].off + s->cap_ext[j].len);
    }
    if (j == i) {
        if (s->cap_next == TCG_CACHE_MAX_EXT) {
            tcg_cache_exclude(s, TCG_CACHE_X_SPAN);
            return;
        }
        memmove(&s->cap_ext[i + 1], &s->cap_ext[i],
                (s->cap_next - i) * sizeof(s->cap_ext[0]));
        s->cap_next++;
    } else if (j > i + 1) {
        memmove(&s->cap_ext[i + 1], &s->cap_ext[j],
                (s->cap_next - j) * sizeof(s->cap_ext[0]));
        s->cap_next -= j - i - 1;
    }
    s->cap_ext[i].off = off;
    s->cap_ext[i].len = end - off;
}

void tcg_cache_acqrel(TCGContext *s, uint64_t pc)
{
    if (!s->cap_on) {
        return;
    }
    if (s->cap_nacq && s->cap_acq[s->cap_nacq - 1] == pc) {
        return;
    }
    if (s->cap_nacq == s->cap_maxacq) {
        s->cap_maxacq = s->cap_maxacq ? s->cap_maxacq * 2 : 32;
        s->cap_acq = g_renew(uint64_t, s->cap_acq, s->cap_maxacq);
    }
    s->cap_acq[s->cap_nacq++] = pc;
}

/* Kinds that resolve to code or data outside the TB. */

static uintptr_t tcg_cache_anchor(void)
{
    return (uintptr_t)tcg_gen_code;
}

/* The last capture's exclusion (statistics). */
unsigned tcg_cache_last_reason;

/* The last failed install's relocation (statistics). */
unsigned tcg_cache_fail_kind, tcg_cache_fail_form;

#ifdef TCG_TARGET_HAS_CACHE

static const void *tcg_cache_stub(unsigned id)
{
    switch (id) {
    case TCG_STUB_EPILOGUE0:
        return tcg_code_gen_epilogue;
    case TCG_STUB_RET:
        return tb_ret_addr;
    case TCG_STUB_XPAGE:
        return tcg_xpage_stub;
    default:
        return NULL;
    }
}

/* QEMU's own image, for the verifier. */
#ifdef _WIN32
extern IMAGE_DOS_HEADER __ImageBase;

static void tcg_cache_image(uintptr_t *lo, uintptr_t *hi)
{
    const IMAGE_NT_HEADERS *nt = (const void *)((const char *)&__ImageBase
                                                + __ImageBase.e_lfanew);

    *lo = (uintptr_t)&__ImageBase;
    *hi = *lo + nt->OptionalHeader.SizeOfImage;
}
#elif defined(CONFIG_USER_ONLY) && defined(CONFIG_LINUX)
extern char __executable_start[], _end[];

static void tcg_cache_image(uintptr_t *lo, uintptr_t *hi)
{
    *lo = (uintptr_t)__executable_start;
    *hi = (uintptr_t)_end;
}
#else
/* Nothing is captured (system mode, other hosts). */
static void tcg_cache_image(uintptr_t *lo, uintptr_t *hi)
{
    *lo = *hi = 0;
}
#endif

/* The captured TB's two parts, as RW and RX ranges. */
typedef struct CapParts {
    uint8_t *hot, *cold;
    uintptr_t hot_rx, cold_rx, tb_rx;
    uint32_t hot_len, code_len, cold_len;
    uint64_t pc;
} CapParts;

static int cap_rec_cmp(const void *a, const void *b)
{
    const TCGCapRec *x = a, *y = b;

    if (x->site != y->site) {
        return (uintptr_t)x->site < (uintptr_t)y->site ? -1 : 1;
    }
    return x->form - y->form;
}

/* The part a byte at @rw lies in: 0 hot, 1 cold, -1 neither. */
static int cap_part_of(const CapParts *p, const void *rw, uint32_t *off)
{
    if ((const uint8_t *)rw >= p->hot
        && (const uint8_t *)rw < p->hot + p->hot_len) {
        *off = (const uint8_t *)rw - p->hot;
        return 0;
    }
    if (p->cold_len && (const uint8_t *)rw >= p->cold
        && (const uint8_t *)rw < p->cold + p->cold_len) {
        *off = (const uint8_t *)rw - p->cold;
        return 1;
    }
    return -1;
}

/* The part code at @rx lies in, ends included (a label at the end). */
static int cap_part_of_rx(const CapParts *p, uintptr_t rx, uint32_t *off)
{
    if (rx >= p->hot_rx && rx <= p->hot_rx + p->hot_len) {
        *off = rx - p->hot_rx;
        return 0;
    }
    if (p->cold_len && rx >= p->cold_rx && rx <= p->cold_rx + p->cold_len) {
        *off = rx - p->cold_rx;
        return 1;
    }
    return -1;
}

static bool cap_form_pcrel(int form)
{
    return form != TCG_CAPF_MOVW && form != TCG_CAPF_POOL64;
}

static bool cap_form_adrp(int form)
{
    return form == TCG_CAPF_ADRP || form == TCG_CAPF_ADRP_ADD
           || form == TCG_CAPF_ADRP_LDR || form == TCG_CAPF_RAW_ADRP;
}

/*
 * A value whose meaning depends on placement: in QEMU's image, in this
 * TB's struct or code, a stub or the chunk's thunk.  Not the rest of the
 * code buffer: the Windows modules put it below 4 GiB, among the values
 * a 32-bit guest uses.
 */
static bool cap_addr_suspect(TCGContext *s, const CapParts *p, uintptr_t v,
                             uintptr_t img_lo, uintptr_t img_hi)
{
    if ((v >= img_lo && v < img_hi)
        || (v >= p->tb_rx && v - p->tb_rx < tb_struct_size(TB_JMP_SLOTS))
        || (v >= p->hot_rx && v - p->hot_rx <= p->hot_len)
        || (p->cold_len && v >= p->cold_rx && v - p->cold_rx <= p->cold_len)
        || (s->lay_thunk && v == (uintptr_t)s->lay_thunk)) {
        return true;
    }
    for (unsigned i = 0; i < TCG_STUB_MAX; i++) {
        if (tcg_cache_stub(i) && v == (uintptr_t)tcg_cache_stub(i)) {
            return true;
        }
    }
    return false;
}

/*
 * Resolve a record's meaning into the artifact's form: 1 kept (*out
 * filled), 0 dropped (it survives any move of its part), or -reason.
 */
static int cap_classify(TCGContext *s, const CapParts *p, const TCGCapRec *r,
                        TCGCacheArtRel *out, uintptr_t img_lo,
                        uintptr_t img_hi)
{
    uint32_t soff, toff;
    int spart = cap_part_of(p, r->site, &soff);
    uintptr_t pc = (uintptr_t)tcg_splitwx_to_rx(r->site), v;
    int tpart, kind = r->kind;

    if (spart < 0) {
        return -TCG_CACHE_X_PROV;
    }
    if (!tcg_cache_decode(r->site, pc, r->form, r->aux, &v)) {
        return -TCG_CACHE_X_PROV;
    }
    if (!cap_form_pcrel(r->form) && v != r->val) {
        return -TCG_CACHE_X_PROV;
    }
    out->site = soff | (spart ? TCG_CACHE_COLD_BIT : 0);
    out->form = r->form;
    out->aux = r->aux;
    out->kind = kind;

    switch (kind) {
    case TCG_CAP_NONE:
        if (r->form == TCG_CAPF_RAW_ADRP) {
            return -TCG_CACHE_X_RAW_ADRP;
        }
        tpart = cap_part_of_rx(p, v, &toff);
        if (tpart < 0) {
            return -TCG_CACHE_X_UNKNOWN_REF;
        }
        if (tpart == spart && !cap_form_adrp(r->form)) {
            return 0;
        }
        out->kind = tpart ? TCG_CAP_COLD : TCG_CAP_HOT;
        out->val = toff;
        return 1;
    case TCG_CAP_ABS:
        /* Unchanged: so never something whose place moves. */
        if (cap_addr_suspect(s, p, v, img_lo, img_hi)) {
            return -TCG_CACHE_X_PROV;
        }
        out->val = v;
        return 1;
    case TCG_CAP_HOT:
    case TCG_CAP_COLD:
        /* Declared a place in the TB's code: which part, by the value. */
        tpart = cap_part_of_rx(p, v, &toff);
        if (tpart < 0) {
            return -TCG_CACHE_X_PROV;
        }
        out->kind = tpart ? TCG_CAP_COLD : TCG_CAP_HOT;
        out->val = toff;
        return 1;
    case TCG_CAP_HELPER:
        out->val = v - tcg_cache_anchor();
        return 1;
    case TCG_CAP_STUB:
        for (unsigned i = 0; i < TCG_STUB_MAX; i++) {
            if (v == (uintptr_t)tcg_cache_stub(i)) {
                out->val = i;
                return 1;
            }
        }
        return -TCG_CACHE_X_PROV;
    case TCG_CAP_OWN_TB:
        if (v - p->tb_rx >= tb_struct_size(TB_JMP_SLOTS)) {
            return -TCG_CACHE_X_PROV;
        }
        out->val = v - p->tb_rx;
        return 1;
    case TCG_CAP_THUNK:
        if (v != (uintptr_t)s->lay_thunk) {
            return -TCG_CACHE_X_PROV;
        }
        out->val = 0;
        return 1;
    default:
        return -TCG_CACHE_X_UNSUPPORTED;
    }
}

/*
 * The verifier: every PC-relative insn in the code has a record, and no
 * MOVZ/MOVK group or pool word holding an address in the code buffer or
 * QEMU's image goes unrecorded.  Sites of @recs (sorted) are RW.
 */
static bool cap_rec_at(const TCGCapRec *recs, int n, const void *site)
{
    int lo = 0, hi = n;

    while (lo < hi) {
        int mid = (lo + hi) / 2;

        if ((uintptr_t)recs[mid].site < (uintptr_t)site) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < n && recs[lo].site == site;
}

static bool cap_verify_range(TCGContext *s, const CapParts *p,
                             const TCGCapRec *recs, int n, uint8_t *start,
                             uint32_t code_len, uint32_t pool_len)
{
    uintptr_t img_lo, img_hi, t;
    const uint32_t *w = (const uint32_t *)start;
    uint32_t nw = code_len / 4;

    int j = 0;

    tcg_cache_image(&img_lo, &img_hi);
    for (uint32_t i = 0; i < nw; i++) {
        const TCGCapRec *r = NULL;
        uint64_t v;
        int k;

        /* Data in code: skip it. */
        while (j < n && (uintptr_t)recs[j].site < (uintptr_t)&w[i]) {
            j++;
        }
        for (int q = j; q < n && recs[q].site == &w[i]; q++) {
            if (recs[q].form == TCG_CAPF_DATA
                || recs[q].form == TCG_CAPF_REL32) {
                r = &recs[q];
            }
        }
        if (r) {
            i += (r->form == TCG_CAPF_DATA ? r->aux / 4 : 1) - 1;
            continue;
        }
        if (tcg_cache_insn_pcrel(&w[i],
                                 (uintptr_t)tcg_splitwx_to_rx((void *)&w[i]),
                                 &t)) {
            if (!cap_rec_at(recs, n, &w[i])) {
                if (tcg_cache_debug) {
                    fprintf(stderr, "verify: pcrel %08x at +%x of %x -> %"
                            PRIxPTR "\n", w[i], i * 4, code_len, t);
                }
                return false;
            }
            continue;
        }
        k = tcg_cache_insn_movw(&w[i], nw - i, &v);
        if (k > 0) {
            if (cap_addr_suspect(s, p, v, img_lo, img_hi)
                && !cap_rec_at(recs, n, &w[i])) {
                if (tcg_cache_debug) {
                    fprintf(stderr, "verify: movw %08x x%d at +%x of %x = %"
                            PRIx64 " (img %" PRIxPTR "-%" PRIxPTR " tb %"
                            PRIxPTR " hot %" PRIxPTR " cold %" PRIxPTR
                            " pc %" PRIx64 ")\n",
                            w[i], k, i * 4, code_len, v, img_lo, img_hi,
                            p->tb_rx, p->hot_rx, p->cold_rx,
                            p->pc);
                }
                return false;
            }
            i += k - 1;
        }
    }
    for (uint32_t o = ROUND_UP(code_len, 8); o + 8 <= code_len + pool_len;
         o += 8) {
        uint64_t v = ldq_he_p(start + o);

        if (cap_addr_suspect(s, p, v, img_lo, img_hi)
            && !cap_rec_at(recs, n, start + o)) {
            if (tcg_cache_debug) {
                fprintf(stderr, "verify: pool +%x = %" PRIx64 "\n", o, v);
            }
            return false;
        }
    }
    return true;
}

/* A slot offset (from the hot part's start) as a place. */
static bool cap_place(const CapParts *p, uint32_t off, uint32_t *place)
{
    if (off == TB_JMP_OFFSET_INVALID) {
        *place = off;
        return true;
    }
    if (off <= p->hot_len) {
        *place = off;
        return true;
    }
    if (p->cold_len) {
        uintptr_t rx = p->hot_rx + off;

        if (rx >= p->cold_rx && rx <= p->cold_rx + p->cold_len) {
            *place = (rx - p->cold_rx) | TCG_CACHE_COLD_BIT;
            return true;
        }
    }
    return false;
}

/* A growable byte buffer, for the artifact. */
typedef struct CapBuf {
    uint8_t *data;
    size_t len, cap;
} CapBuf;

static void cap_buf_size(CapBuf *b, size_t len)
{
    if (len > b->cap) {
        b->cap = MAX(len, b->cap * 2);
        b->data = g_realloc(b->data, b->cap);
    }
    if (len > b->len) {
        memset(b->data + b->len, 0, len - b->len);
    }
    b->len = len;
}

static void cap_buf_add(CapBuf *b, const void *p, size_t n)
{
    size_t at = b->len;

    cap_buf_size(b, at + n);
    memcpy(b->data + at, p, n);
}

static void cap_reject(TCGContext *s, unsigned reason)
{
    tcg_cache_stats.excluded[reason]++;
    tcg_cache_last_reason = reason;
}

void *tcg_cache_capture(TCGContext *s, TranslationBlock *tb,
                        const void *search, size_t search_len, size_t *lenp)
{
    int64_t t0 = TCG_CACHE_CLOCK(), t1;
    size_t search_at;
    CapParts p;
    TCGCacheArt h = { };
    TCGCacheArtRel *rels;
    TCGCacheArtCon *cons;
    TCGCacheArtSlot *slots;
    TCGCapRec *recs = s->cap_rec;
    int n = s->cap_nrec, nrel = 0, ncon = 0, m, i;
    uint32_t ext_bytes = 0;
    CapBuf ab = { }, *a = &ab;
    size_t hot_at, cold_at;
    uintptr_t img_lo, img_hi;
    uint8_t *hot, *cold;

    tcg_cache_stats.tried++;
    if (s->cap_excl) {
        cap_reject(s, s->cap_excl);
        return NULL;
    }
    /*
     * Code from no guest bytes (x86's vsyscall page, which raises an
     * exception without reading it): nothing to validate it by.
     */
    if (!s->cap_next) {
        cap_reject(s, TCG_CACHE_X_FAKE);
        return NULL;
    }
#ifdef CONFIG_USER_ONLY
    if (tb->smc_check || tb->smc_inline) {
        cap_reject(s, TCG_CACHE_X_SMC);
        return NULL;
    }
#endif
    if (s->cap_fail) {
        cap_reject(s, s->cap_fail);
        return NULL;
    }

    p.hot = (uint8_t *)tcg_splitwx_to_rw(tb->tc.ptr);
    p.hot_rx = (uintptr_t)tb->tc.ptr;
    p.hot_len = tb->tc.size;
    p.code_len = s->data_gen_ptr
                 ? (uint8_t *)s->data_gen_ptr - p.hot : p.hot_len;
    p.cold = s->cap_cold;
    p.cold_len = s->cap_cold ? (uint8_t *)s->cap_cold_end - p.cold : 0;
    p.cold_rx = p.cold ? (uintptr_t)tcg_splitwx_to_rx(p.cold) : 0;
    p.tb_rx = (uintptr_t)tcg_splitwx_to_rx(tb);
    p.pc = tb->pc;

#ifdef CONFIG_USER_ONLY
    /* The lazy-sync map's offsets are from the hot part's start. */
    for (i = 0; i < s->nb_lazy_map; i++) {
        if (s->lazy_map[i].end > p.code_len) {
            cap_reject(s, TCG_CACHE_X_LAZY);
            return NULL;
        }
    }
#endif

    /* Merge the records at each site: patches and emissions. */
    qsort(recs, n, sizeof(*recs), cap_rec_cmp);
    for (i = 0, m = 0; i < n; i++) {
        TCGCapRec *r = &recs[i];

        if (m && recs[m - 1].site == r->site && r->form != TCG_CAPF_CON
            && recs[m - 1].form != TCG_CAPF_CON) {
            TCGCapRec *q = &recs[m - 1];

            if (q->form != r->form) {
                if (q->form == TCG_CAPF_RAW_ADRP && cap_form_adrp(r->form)) {
                    q->form = r->form;
                    q->aux = r->aux;
                } else if (!(r->form == TCG_CAPF_RAW_ADRP
                             && cap_form_adrp(q->form))) {
                    cap_reject(s, TCG_CACHE_X_PROV);
                    return NULL;
                }
            }
            if (q->kind == TCG_CAP_NONE) {
                q->kind = r->kind;
                q->val = r->val;
            } else if (r->kind != TCG_CAP_NONE
                       && (r->kind != q->kind || r->val != q->val)) {
                cap_reject(s, TCG_CACHE_X_PROV);
                return NULL;
            }
            continue;
        }
        recs[m++] = *r;
    }
    n = m;

    if (tcg_cache_verify_on
        && (!cap_verify_range(s, &p, recs, n, p.hot, p.code_len,
                              p.hot_len - p.code_len)
            || (p.cold_len
                && !cap_verify_range(s, &p, recs, n, p.cold, p.cold_len,
                                     0)))) {
        cap_reject(s, TCG_CACHE_X_VERIFY);
        return NULL;
    }

    tcg_cache_image(&img_lo, &img_hi);
    rels = g_newa(TCGCacheArtRel, n + 1);
    cons = g_newa(TCGCacheArtCon, n + 1);
    for (i = 0; i < n; i++) {
        TCGCapRec *r = &recs[i];
        int ret;

        if (r->form == TCG_CAPF_DATA) {
            continue;
        }
        if (r->form == TCG_CAPF_CON) {
            uint32_t off;
            int part = cap_part_of(&p, r->site, &off);

            if (part < 0) {
                cap_reject(s, TCG_CACHE_X_PROV);
                return NULL;
            }
            cons[ncon].site = off | (part ? TCG_CACHE_COLD_BIT : 0);
            cons[ncon].kind = r->kind;
            cons[ncon].slot = r->aux;
            cons[ncon].pad = 0;
            ncon++;
            continue;
        }
        ret = cap_classify(s, &p, r, &rels[nrel], img_lo, img_hi);
        if (ret < 0) {
            cap_reject(s, -ret);
            return NULL;
        }
        nrel += ret;
    }

    /* The header. */
    h.magic = TCG_CACHE_MAGIC;
    h.version = TCG_CACHE_VERSION;
    /* The pages tb_record will give the TB, from its size. */
    h.flags = (s->lay_on ? TCG_CACHE_ART_SPLIT : 0)
              | (((tb->pc + tb->size - 1) ^ tb->pc) & TARGET_PAGE_MASK
                 ? TCG_CACHE_ART_PAGE2 : 0);
    h.nb_slots = tb->nb_slots;
    h.n_rel = nrel;
    h.n_con = ncon;
    h.n_acq = s->cap_nacq;
    h.n_ext = s->cap_next;
    h.size = tb->size;
    h.icount = tb->icount;
    h.jmp_call = tb->jmp_call;
    h.jmp_cold = tb->jmp_cold;
    h.jmp_far = tb->jmp_far;
    h.loops = tb->loops;
    h.edge_end = tb->edge_end;
    h.chain_dead_in = tb->chain_dead_in;
    h.tb_flags = tb->flags;
    h.cflags = tb->cflags;
    h.pc = tb->pc;
    h.cs_base = tb->cs_base;
    h.hot_len = p.hot_len;
    h.pool_off = p.code_len;
    h.cold_len = p.cold_len;
    h.search_len = search_len;
    for (i = 0; i < s->cap_next; i++) {
        ext_bytes += s->cap_ext[i].len;
    }
    h.ext_bytes = ext_bytes;

    slots = g_newa(TCGCacheArtSlot, tb->nb_slots + 1);
    for (i = 0; i < tb->nb_slots; i++) {
        uint32_t cond = tb->jmp[i].cond;

        memset(&slots[i], 0, sizeof(slots[i]));
        if (!cap_place(&p, tb->jmp[i].reset_offset, &slots[i].reset)
            || !cap_place(&p, tb->jmp[i].insn_offset, &slots[i].insn)
            || (cond && !cap_place(&p, cond - 1, &slots[i].cond))) {
            cap_reject(s, TCG_CACHE_X_PROV);
            return NULL;
        }
        slots[i].cond += cond ? 1 : 0;
        slots[i].dead = tb->jmp[i].dead;
    }

    cap_buf_size(a, 0);
    cap_buf_add(a, (void *)&h, sizeof(h));
    cap_buf_add(a, (void *)slots, sizeof(*slots) * h.nb_slots);
    cap_buf_add(a, (void *)rels, sizeof(*rels) * nrel);
    cap_buf_add(a, (void *)cons, sizeof(*cons) * ncon);
    cap_buf_add(a, (void *)s->cap_acq, 8 * h.n_acq);
    cap_buf_add(a, (void *)s->cap_ext, sizeof(*s->cap_ext) * h.n_ext);
    for (i = 0; i < s->cap_next; i++) {
        cap_buf_add(a, s->cap_bytes + s->cap_ext[i].off,
                            s->cap_ext[i].len);
    }
    cap_buf_size(a, ROUND_UP(a->len, 8));

    /* The code, canonical: every relocated field zeroed. */
    hot_at = a->len;
    cap_buf_add(a, p.hot, p.hot_len);
    cap_buf_size(a, ROUND_UP(a->len, 8));
    cold_at = a->len;
    if (p.cold_len) {
        cap_buf_add(a, p.cold, p.cold_len);
    }
    cap_buf_size(a, ROUND_UP(a->len, 8));
    search_at = a->len;
    cap_buf_add(a, search, search_len);
    cap_buf_size(a, ROUND_UP(a->len, 8));
    hot = a->data + hot_at;
    cold = a->data + cold_at;
    for (i = 0; i < nrel; i++) {
        uint32_t site = rels[i].site;
        uint8_t *at = site & TCG_CACHE_COLD_BIT
                      ? cold + (site & ~TCG_CACHE_COLD_BIT) : hot + site;

        tcg_cache_zero(at, rels[i].form, rels[i].aux);
        tcg_cache_stats.rel_kind[rels[i].kind]++;
        tcg_cache_stats.rel_form[rels[i].form]++;
    }
    ((TCGCacheArt *)a->data)->len = a->len;
    /* What a reader would refuse isn't kept. */
    if (a->len > TCG_CACHE_ART_MAX || nrel > TCG_CACHE_MAX_REL
        || h.n_acq > TCG_CACHE_MAX_ACQ) {
        g_free(a->data);
        cap_reject(s, TCG_CACHE_X_TOO_MANY);
        return NULL;
    }
    /*
     * Every check a reader makes depends only on the artifact's bytes and
     * on what the fingerprint pins, so an artifact this build validates
     * here validates wherever it is read.  One that doesn't is a producer
     * bug: the TB runs as translated, and its artifact goes nowhere.
     */
    if (unlikely(tcg_cache_test_capture_damage)) {
        static unsigned damage_n;

        if (++damage_n % tcg_cache_test_capture_damage == 0
            && tcg_cache_unwind_damage(a->data + search_at, search_len,
                                       tb->icount,
                                       TCG_CACHE_DAMAGE_TRUNCATED)) {
            tcg_cache_stats.test_capture_damaged++;
        }
    }
    t1 = TCG_CACHE_CLOCK();
    if (tcg_cache_validate(a->data, a->len)) {
        g_free(a->data);
        cap_reject(s, TCG_CACHE_X_INVALID);
        tcg_cache_stats.capture_val_ns += TCG_CACHE_CLOCK() - t1;
        tcg_cache_stats.capture_ns += TCG_CACHE_CLOCK() - t0;
        return NULL;
    }
    tcg_cache_stats.capture_val_ns += TCG_CACHE_CLOCK() - t1;
    if (unlikely(tcg_cache_test_capture_damage_after)) {
        static unsigned damage_after_n;

        if (++damage_after_n % tcg_cache_test_capture_damage_after == 0
            && tcg_cache_unwind_damage(a->data + search_at, search_len,
                                       tb->icount,
                                       TCG_CACHE_DAMAGE_TRUNCATED)) {
            tcg_cache_stats.test_capture_damaged++;
        }
    }

    tcg_cache_stats.captured++;
    tcg_cache_stats.bytes += a->len;
    tcg_cache_stats.hot_bytes += p.hot_len;
    tcg_cache_stats.cold_bytes += p.cold_len;
    tcg_cache_stats.search_bytes += search_len;
    tcg_cache_stats.ext_total += ext_bytes;
    tcg_cache_stats.capture_ns += TCG_CACHE_CLOCK() - t0;
    *lenp = a->len;
    return a->data;
}

#else

void *tcg_cache_capture(TCGContext *s, TranslationBlock *tb,
                        const void *search, size_t search_len, size_t *lenp)
{
    return NULL;
}

#endif /* TCG_TARGET_HAS_CACHE */

/* Locate and bounds-check an artifact's arrays and parts. */
bool tcg_cache_art_view(const void *art, size_t len, TCGCacheArtView *v)
{
    const TCGCacheArt *h = art;
    size_t o = sizeof(*h);
    const uint8_t *b = art;

#define TAKE(field, type, count) do {                           \
        size_t sz_ = (size_t)(count) * sizeof(type);            \
        if (o + sz_ > len) {                                    \
            if (tcg_cache_debug) {                   \
                fprintf(stderr, "view: %s o=%zu sz=%zu len=%zu\n", \
                        #field, o, sz_, len);                   \
            }                                                   \
            return false;                                       \
        }                                                       \
        v->field = (const void *)(b + o);                       \
        o += sz_;                                               \
    } while (0)

    if (len < sizeof(*h) || h->magic != TCG_CACHE_MAGIC
        || h->version != TCG_CACHE_VERSION || h->len != len
        || h->nb_slots > TB_JMP_SLOTS) {
        if (tcg_cache_debug) {
            fprintf(stderr, "view: hdr len %zu/%u magic %x\n", len,
                    len >= sizeof(*h) ? h->len : 0, h->magic);
        }
        return false;
    }
    v->h = h;
    TAKE(slot, TCGCacheArtSlot, h->nb_slots);
    TAKE(rel, TCGCacheArtRel, h->n_rel);
    TAKE(con, TCGCacheArtCon, h->n_con);
    TAKE(acq, uint64_t, h->n_acq);
    TAKE(ext, TCGCacheArtExt, h->n_ext);
    TAKE(ext_bytes, uint8_t, h->ext_bytes);
    o = ROUND_UP(o, 8);
    TAKE(hot, uint8_t, h->hot_len);
    o = ROUND_UP(o, 8);
    TAKE(cold, uint8_t, h->cold_len);
    o = ROUND_UP(o, 8);
    TAKE(search, uint8_t, h->search_len);
#undef TAKE
    return h->pool_off <= h->hot_len;
}

/*
 * Reserve places for @v in the current layout, without changing it: the
 * chunk tcg_tb_alloc would use now (split), or the packed code stream.
 * Any transition (a new chunk or region) is left to translation.
 */
bool tcg_cache_reserve(TCGContext *s, const TCGCacheArtView *v,
                       TCGCacheRes *r)
{
    const TCGCacheArt *h = v->h;
    size_t size = tb_struct_size(h->nb_slots);
    uint8_t *p = s->code_gen_ptr;
    uintptr_t skew_hot = 0, skew_cold = 0;

    if (!p) {
        return false;
    }
    if (tcg_cache_skew) {
        uint32_t x = (uintptr_t)p * 2654435761u >> 7;

        skew_hot = (x % tcg_cache_skew) * 16;
        skew_cold = ((x >> 12) % tcg_cache_skew) * 16;
    }
    memset(r, 0, sizeof(*r));
    if (h->flags & TCG_CACHE_ART_SPLIT) {
        uint8_t *tb, *cold, *search, *end, *hot;

        /* tb_layout_chunk's test for keeping the current chunk. */
        if (!tcg_tblayout || !s->lay_chunk || p < (uint8_t *)s->lay_chunk
            || p + TBLAYOUT_RESERVE > (uint8_t *)s->lay_hot_end
            || (uint8_t *)s->lay_cold + TBLAYOUT_RESERVE
               > (uint8_t *)s->lay_cold_end) {
            return false;
        }
        tb = (void *)ROUND_UP((uintptr_t)s->lay_cold + skew_cold,
                              TCG_TBPACK_ALIGN);
        cold = (void *)ROUND_UP((uintptr_t)tb + size, TCG_TBPACK_ALIGN);
        search = (void *)ROUND_UP((uintptr_t)cold + h->cold_len, 16);
        end = (void *)ROUND_UP((uintptr_t)search + h->search_len,
                               CODE_GEN_ALIGN);
        hot = (void *)ROUND_UP((uintptr_t)p + skew_hot, CODE_GEN_ALIGN);
        if (end > (uint8_t *)tcg_tb_data_highwater(s)
            || hot + h->hot_len > (uint8_t *)s->lay_hot_end - TCG_HIGHWATER) {
            return false;
        }
        r->split = true;
        r->tb = tb;
        r->hot = hot;
        r->cold = cold;
        r->search = search;
        r->lay_cold = end;
        r->code_gen_ptr = (void *)ROUND_UP((uintptr_t)hot + h->hot_len,
                                           CODE_GEN_ALIGN);
        r->thunk = s->lay_thunk;
    } else {
        uintptr_t align = tcg_tbpack ? TCG_TBPACK_ALIGN
                                     : qemu_icache_linesize;
        uint8_t *tb, *hot, *end;

        /* Packed: without the layout, or after the region's last chunk. */
        if (tcg_tblayout && s->lay_chunk) {
            return false;
        }
        if (h->cold_len) {
            return false;
        }
        tb = (void *)ROUND_UP((uintptr_t)p + skew_hot, align);
        hot = (void *)ROUND_UP((uintptr_t)tb + size, align);
        end = (void *)ROUND_UP((uintptr_t)hot + h->hot_len + h->search_len,
                               CODE_GEN_ALIGN);
        if (end > (uint8_t *)s->code_gen_highwater) {
            return false;
        }
        r->tb = tb;
        r->hot = hot;
        r->cold = hot + h->hot_len;
        r->search = hot + h->hot_len;
        r->code_gen_ptr = end;
    }
    return true;
}

#ifdef TCG_TARGET_HAS_CACHE
/* A place in the new TB: RW and RX. */
static uint8_t *res_at(const TCGCacheRes *r, uint32_t place, uintptr_t *rx)
{
    uint8_t *rw = place & TCG_CACHE_COLD_BIT
                  ? (uint8_t *)r->cold + (place & ~TCG_CACHE_COLD_BIT)
                  : (uint8_t *)r->hot + place;

    *rx = (uintptr_t)tcg_splitwx_to_rx(rw);
    return rw;
}

/* Whether the 4-byte insn at @rx lies within the placed hot or cold code. */
static bool res_code_insn(const TCGCacheArt *h, uintptr_t hot_rx,
                          uintptr_t cold_rx, uintptr_t rx)
{
    if (rx & 3) {
        return false;
    }
    if (rx >= hot_rx && h->hot_len >= 4 && rx - hot_rx <= h->hot_len - 4) {
        return true;
    }
    return h->cold_len >= 4 && rx >= cold_rx && rx - cold_rx <= h->cold_len - 4;
}

/* A place as an offset from the new hot part, for the slots. */
static uint32_t res_off(const TCGCacheRes *r, uint32_t place)
{
    uintptr_t rx;

    if (place == TB_JMP_OFFSET_INVALID) {
        return place;
    }
    res_at(r, place, &rx);
    return rx - (uintptr_t)tcg_splitwx_to_rx(r->hot);
}
#endif

TranslationBlock *tcg_cache_place(TCGContext *s, const TCGCacheArtView *v,
                                  const TCGCacheRes *r)
{
#ifdef TCG_TARGET_HAS_CACHE
    const TCGCacheArt *h = v->h;
    TranslationBlock *tb = r->tb;
    uintptr_t tb_rx = (uintptr_t)tcg_splitwx_to_rx(tb);
    uintptr_t hot_rx = (uintptr_t)tcg_splitwx_to_rx(r->hot);

    /* Poison the struct: every field must be written below. */
    memset(tb, 0xa5, tb_struct_size(h->nb_slots));
    memcpy(r->hot, v->hot, h->hot_len);
    memcpy(r->cold, v->cold, h->cold_len);
    memcpy(r->search, v->search, h->search_len);

    tb->pc = h->pc;
    tb->cs_base = h->cs_base;
    tb->flags = h->tb_flags;
    tb->cflags = h->cflags;
    tb->loops = h->loops;
    tb->edge_end = h->edge_end;
    tb->size = h->size;
    tb->icount = h->icount;
    tb->tc.ptr = (void *)hot_rx;
    tb->tc.size = h->hot_len;
    tb->tc.search = tcg_splitwx_to_rx(r->search);
    /* Ordered before publication by the installer's, as every field. */
    tb->search_len = h->search_len;
    tb->code_len = h->pool_off;
    tb->unwind_unchecked = 1;
    if (unlikely(tcg_cache_test_unwind_damage)
        && tcg_cache_unwind_damage(r->search, h->search_len, h->icount,
                                   tcg_cache_test_unwind_damage)) {
        tcg_cache_stats.test_unwind_damaged++;
    }
#ifdef CONFIG_USER_ONLY
    memset(&tb->itree, 0, sizeof(tb->itree));
    tb->smc_check = false;
    tb->smc_reject = false;
    tb->smc_inline = false;
    tb->smc_len = 0;
    tb->smc_check_end = 0;
    tb->smc_crc = 0;
    tb->smc_stale = NULL;
#else
    tb->page_next[0] = tb->page_next[1] = 0;
    tb->page_addr[0] = tb->page_addr[1] = -1;
#endif
    qemu_spin_init(&tb->jmp_lock);
    tb->jmp_call = h->jmp_call;
    tb->chain_dead_in = h->chain_dead_in;
    tb->jmp_cold = h->jmp_cold;
    tb->jmp_far = h->jmp_far;
    tb->nb_slots = h->nb_slots;
    tb->jmp_list_head = 0;
    for (int n = 0; n < h->nb_slots; n++) {
        const TCGCacheArtSlot *sl = &v->slot[n];

        if (sl->dead > h->nb_slots) {
            return NULL;
        }
        tb->jmp[n].reset_offset = res_off(r, sl->reset);
        tb->jmp[n].insn_offset = res_off(r, sl->insn);
        tb->jmp[n].cond = sl->cond ? res_off(r, sl->cond - 1) + 1 : 0;
        /* tb_set_cond_link points the branch at the slot: in its reach. */
        if (sl->cond) {
            int64_t d = (int64_t)tb->jmp[n].insn_offset
                        - (int64_t)(tb->jmp[n].cond - 1);

            if ((d & 3) || d != sextract64(d, 0, 21)) {
                return NULL;
            }
        }
        tb->jmp[n].dead = sl->dead;
        tb->jmp[n].target_addr = 0;
        tb->jmp[n].list_next = 0;
        tb->jmp[n].dest = 0;
    }

    for (int i = 0; i < h->n_rel; i++) {
        const TCGCacheArtRel *rel = &v->rel[i];
        uintptr_t rx, val;
        uint8_t *rw = res_at(r, rel->site, &rx);

        switch (rel->kind) {
        case TCG_CAP_ABS:
            val = rel->val;
            break;
        case TCG_CAP_HELPER:
            val = tcg_cache_anchor() + rel->val;
            break;
        case TCG_CAP_STUB:
            val = (uintptr_t)tcg_cache_stub(rel->val);
            if (!val) {
                tcg_cache_fail_kind = rel->kind;
                tcg_cache_fail_form = rel->form;
                return NULL;
            }
            break;
        case TCG_CAP_OWN_TB:
            val = tb_rx + rel->val;
            break;
        case TCG_CAP_THUNK:
            if (!r->thunk) {
                tcg_cache_fail_kind = rel->kind;
                tcg_cache_fail_form = rel->form;
                return NULL;
            }
            val = (uintptr_t)r->thunk;
            break;
        case TCG_CAP_HOT:
            val = hot_rx + rel->val;
            break;
        case TCG_CAP_COLD:
            val = (uintptr_t)tcg_splitwx_to_rx(r->cold) + rel->val;
            break;
        default:
            tcg_cache_fail_kind = TCG_CAP_UNSUPPORTED;
            tcg_cache_fail_form = rel->form;
            return NULL;
        }
        if (!tcg_cache_apply(rw, rx, rel->form, rel->aux, val)) {
            tcg_cache_fail_kind = rel->kind;
            tcg_cache_fail_form = rel->form;
            if (tcg_cache_debug) {
                fprintf(stderr, "reloc: form %d kind %d aux %x site %x "
                        "val %" PRIx64 " -> %" PRIxPTR " at %" PRIxPTR "\n",
                        rel->form, rel->kind, rel->aux, rel->site, rel->val,
                        val, rx);
            }
            return NULL;
        }
    }

    for (int i = 0; i < h->n_con; i++) {
        const TCGCacheArtCon *c = &v->con[i];
        uintptr_t rx, fa;
        intptr_t off;

        tcg_cache_fail_kind = TCG_CAP_NONE;
        tcg_cache_fail_form = TCG_CAPF_LDRLIT19;
        if (c->kind != TCG_CAPC_SLOT_LDRLIT || c->slot >= h->nb_slots) {
            return NULL;
        }
        res_at(r, c->site, &rx);
        fa = (uintptr_t)tcg_splitwx_to_rx(&tb->jmp[c->slot].target_addr);
        off = fa - rx;
        if (off != sextract64(off, 0, 21)) {
            return NULL;
        }
    }

    /*
     * Each slot in its reset state, as tb_reset_jump sets it but without
     * cache maintenance: tcg_cache_commit synchronizes the whole TB once,
     * before it is published.
     */
    for (int n = 0; n < h->nb_slots; n++) {
        uintptr_t cold_rx = (uintptr_t)tcg_splitwx_to_rx(r->cold);
        uintptr_t jmp_rx;

        if (tb->jmp[n].reset_offset == TB_JMP_OFFSET_INVALID) {
            continue;
        }
        jmp_rx = hot_rx + tb->jmp[n].insn_offset;
        if (!res_code_insn(h, hot_rx, cold_rx, jmp_rx)
            || (tb->jmp[n].cond
                && !res_code_insn(h, hot_rx, cold_rx,
                                  hot_rx + tb->jmp[n].cond - 1))) {
            tcg_cache_fail_kind = TCG_CAP_NONE;
            tcg_cache_fail_form = TCG_CAPF_B26;
            return NULL;
        }
        tb->jmp[n].target_addr = hot_rx + tb->jmp[n].reset_offset;
        tb_jmp_write((const TranslationBlock *)tb_rx, n, jmp_rx,
                     jmp_rx - tcg_splitwx_diff, false);
    }
    return tb;
#else
    return NULL;
#endif
}

void tcg_cache_commit(TCGContext *s, const TCGCacheRes *r)
{
#ifndef CONFIG_TCG_INTERPRETER
    /* The packed layout's cold code and unwind data follow its hot code. */
    size_t cold_len = r->split ? (uint8_t *)r->lay_cold - (uint8_t *)r->cold
                               : 0;

    flush_idcache_range2((uintptr_t)tcg_splitwx_to_rx(r->hot),
                         (uintptr_t)r->hot,
                         (uint8_t *)r->code_gen_ptr - (uint8_t *)r->hot,
                         (uintptr_t)tcg_splitwx_to_rx(r->cold),
                         (uintptr_t)r->cold, cold_len);
#endif
    if (r->split) {
        s->lay_cold = r->lay_cold;
    }
    qatomic_set(&s->code_gen_ptr, r->code_gen_ptr);
}

/*
 * The store (TCG_CACHE_ON): an open-addressed table of keys, each with its
 * candidates newest first.  The caller holds mmap_lock.
 */
typedef struct CacheEnt {
    struct CacheEnt *older;
    uint64_t id, rva, cs_base, base;
    uint32_t flags, cflags;
    size_t len;
    void *art;
} CacheEnt;

static CacheEnt **cache_tab;
static size_t cache_size, cache_keys, cache_bytes;

static uint32_t cache_hash(uint64_t id, uint64_t rva, uint32_t flags,
                           uint64_t cs_base, uint32_t cflags)
{
    return qemu_xxhash8(id, rva, cs_base, flags, cflags);
}

static bool cache_key_eq(const CacheEnt *e, uint64_t id, uint64_t rva,
                         uint32_t flags, uint64_t cs_base, uint32_t cflags)
{
    return e->id == id && e->rva == rva && e->flags == flags &&
           e->cs_base == cs_base && e->cflags == cflags;
}

static CacheEnt **cache_slot(uint64_t id, uint64_t rva, uint32_t flags,
                             uint64_t cs_base, uint32_t cflags)
{
    size_t i = cache_hash(id, rva, flags, cs_base, cflags) & (cache_size - 1);

    while (cache_tab[i] &&
           !cache_key_eq(cache_tab[i], id, rva, flags, cs_base, cflags)) {
        i = (i + 1) & (cache_size - 1);
    }
    return &cache_tab[i];
}

static void cache_grow(void)
{
    CacheEnt **old = cache_tab;
    size_t n = cache_size;

    cache_size = n ? n * 2 : 4096;
    cache_tab = g_new0(CacheEnt *, cache_size);
    for (size_t i = 0; i < n; i++) {
        CacheEnt *e = old[i];

        if (e) {
            *cache_slot(e->id, e->rva, e->flags, e->cs_base, e->cflags) = e;
        }
    }
    g_free(old);
}

const char *tcg_cache_store_put(const TCGCacheImage *img, void *art,
                                size_t len)
{
    const TCGCacheArt *h = art;
    uint64_t rva = h->pc - img->base;
    CacheEnt **slot, *e, **pp;
    int n;

    if (cache_bytes + len + sizeof(CacheEnt) > tcg_cache_max) {
        tcg_cache_stats.store_full++;
        g_free(art);
        return "full";
    }
    if (cache_keys * 2 >= cache_size) {
        cache_grow();
    }
    slot = cache_slot(img->id, rva, h->tb_flags, h->cs_base, h->cflags);
    for (e = *slot; e; e = e->older) {
        if (e->base == img->base && e->len == len &&
            !memcmp(e->art, art, len)) {
            tcg_cache_stats.store_dup++;
            g_free(art);
            return "dup";
        }
    }
    e = g_new(CacheEnt, 1);
    *e = (CacheEnt){
        .older = *slot, .id = img->id, .rva = rva, .cs_base = h->cs_base,
        .base = img->base, .flags = h->tb_flags, .cflags = h->cflags,
        .len = len, .art = art,
    };
    if (!*slot) {
        cache_keys++;
    }
    *slot = e;
    cache_bytes += len + sizeof(CacheEnt);
    tcg_cache_stats.stored++;
    tcg_cache_stats.store_bytes = cache_bytes;

    /* The oldest candidate past the limit goes. */
    for (n = 1, pp = &e->older; *pp; pp = &(*pp)->older, n++) {
        if (n == TCG_CACHE_CANDS) {
            CacheEnt *x = *pp;

            *pp = NULL;
            while (x) {
                CacheEnt *next = x->older;

                cache_bytes -= x->len + sizeof(CacheEnt);
                g_free(x->art);
                g_free(x);
                x = next;
            }
            break;
        }
    }
    return "stored";
}

int tcg_cache_store_find(uint64_t id, uint64_t rva, uint32_t flags,
                         uint64_t cs_base, uint32_t cflags, TCGCacheCand *c)
{
    CacheEnt *e;
    int n = 0;

    if (!cache_size) {
        return 0;
    }
    for (e = *cache_slot(id, rva, flags, cs_base, cflags);
         e && n < TCG_CACHE_CANDS; e = e->older) {
        c[n++] = (TCGCacheCand){ .art = e->art, .len = e->len,
                                 .base = e->base };
    }
    return n;
}

void tcg_cache_store_foreach(void (*fn)(void *opaque, uint64_t id,
                                        uint64_t rva, uint64_t base,
                                        const void *art, size_t len),
                             void *opaque)
{
    for (size_t i = 0; i < cache_size; i++) {
        for (CacheEnt *e = cache_tab[i]; e; e = e->older) {
            fn(opaque, e->id, e->rva, e->base, e->art, e->len);
        }
    }
}

static uint64_t fnv64(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;

    for (size_t i = 0; i < n; i++) {
        h = (h ^ b[i]) * 0x100000001b3ull;
    }
    return h;
}

uint64_t tcg_cache_art_ghash(const void *art, size_t len)
{
    TCGCacheArtView v;
    uint64_t gh = 0xcbf29ce484222325ull;

    if (!tcg_cache_art_view(art, len, &v)) {
        return 0;
    }
    gh = fnv64(gh, v.ext, v.h->n_ext * sizeof(*v.ext));
    return fnv64(gh, v.ext_bytes, v.h->ext_bytes);
}

int tcg_cache_dump_line(char *buf, size_t size, uint64_t id, uint64_t rva,
                        uint64_t base, const void *art, size_t len)
{
    const TCGCacheArt *h = art;

    if (len < sizeof(*h)) {
        return 0;
    }
    return snprintf(buf, size, "cache %016" PRIx64 " %" PRIx64 " %" PRIx64
                    " %x %" PRIx64 " %x %016" PRIx64 " %016" PRIx64 " %zu\n",
                    id, rva, base, h->tb_flags, h->cs_base, h->cflags,
                    tcg_cache_art_ghash(art, len),
                    fnv64(0xcbf29ce484222325ull, art, len), len);
}

void tcg_cache_print_stats(void)
{
    static const char *const why[] = {
        "none", "helper", "stub", "thunk", "reloc", "key-pc", "key", "other",
    };
    TCGCacheStats *t = &tcg_cache_stats;
    static const char *const kinds[] = {
        "none", "abs", "helper", "stub", "own-tb", "thunk", "hot", "cold",
        "unsupported",
    };
    static const char *const forms[] = {
        "none", "b26", "bcond19", "tbz14", "ldrlit19", "adr21", "adrp",
        "adrp+add", "adrp+ldr", "raw-adrp", "movw", "pool64", "rel32",
    };

    fprintf(stderr, "xtcg-cache: tried %" PRIu64 " captured %" PRIu64
            " bytes %" PRIu64 " (hot %" PRIu64 " cold %" PRIu64
            " search %" PRIu64 " guest %" PRIu64 ") capture %.3f ms\n",
            t->tried, t->captured, t->bytes, t->hot_bytes, t->cold_bytes,
            t->search_bytes, t->ext_total, t->capture_ns / 1e6);
    fprintf(stderr, "xtcg-cache: capture validation %.3f ms\n",
            t->capture_val_ns / 1e6);
    fprintf(stderr, "xtcg-cache: unwind first use: restore %" PRIu64
            " lazysync %" PRIu64 " repeats %" PRIu64 " (%.3f ms)"
            " tb struct %zu; installed TBs' writebacks %" PRIu64 "\n",
            t->unwind_checks[TCG_CACHE_UNWIND_RESTORE],
            t->unwind_checks[TCG_CACHE_UNWIND_LAZYSYNC], t->unwind_repeats,
            t->unwind_ns / 1e6, sizeof(TranslationBlock),
            t->unwind_installed_wb);
    if (tcg_cache_test_unwind_damage || tcg_cache_test_capture_damage
        || tcg_cache_test_capture_damage_after) {
        fprintf(stderr, "xtcg-cache: test damage: installs %" PRIu64
                " captures %" PRIu64 "\n", t->test_unwind_damaged,
                t->test_capture_damaged);
    }
    fprintf(stderr, "xtcg-cache: excluded");
    for (int i = 1; i < TCG_CACHE_X_MAX; i++) {
        if (t->excluded[i]) {
            fprintf(stderr, " %s=%" PRIu64, tcg_cache_x_names[i],
                    t->excluded[i]);
        }
    }
    fprintf(stderr, "\nxtcg-cache: relocs");
    for (int i = 0; i < ARRAY_SIZE(kinds); i++) {
        if (t->rel_kind[i]) {
            fprintf(stderr, " %s=%" PRIu64, kinds[i], t->rel_kind[i]);
        }
    }
    fprintf(stderr, " |");
    for (int i = 0; i < ARRAY_SIZE(forms); i++) {
        if (t->rel_form[i]) {
            fprintf(stderr, " %s=%" PRIu64, forms[i], t->rel_form[i]);
        }
    }
    fprintf(stderr, "\nxtcg-cache: installs %" PRIu64 " (%.3f ms) fail:"
            " reserve=%" PRIu64 " reloc=%" PRIu64 " bytes=%" PRIu64
            " con=%" PRIu64 " promoted=%" PRIu64 " key=%" PRIu64
            " dup=%" PRIu64 "\n",
            t->installs, t->install_ns / 1e6, t->inst_fail_reserve,
            t->inst_fail_reloc, t->inst_fail_bytes, t->inst_fail_con,
            t->inst_fail_promoted, t->inst_fail_key, t->inst_dup);
    if (tcg_cache_mode != TCG_CACHE_ON) {
        return;
    }
    fprintf(stderr, "xtcg-cache: on: translations %" PRIu64
            " ineligible %" PRIu64 " stored %" PRIu64 " (%" PRIu64
            " bytes) dup %" PRIu64 " full %" PRIu64 " flushes %" PRIu64
            "\n", t->translations, t->inel_capture, t->stored,
            t->store_bytes, t->store_dup, t->store_full, t->flushes);
    fprintf(stderr, "xtcg-cache: on: lookups %" PRIu64 " ineligible %"
            PRIu64 " none %" PRIu64 " hits %" PRIu64 " miss: base=%" PRIu64
            " struct=%" PRIu64 " region=%" PRIu64 " inel=%" PRIu64
            " fault=%" PRIu64 " inj-promote=%" PRIu64 "\n",
            t->lookups, t->look_inel, t->look_none, t->hits, t->miss_base,
            t->miss_struct, t->miss_region, t->miss_inel, t->miss_fault,
            t->inj_promote);
    fprintf(stderr, "xtcg-cache: on: guard not restored %" PRIu64 "\n",
            t->guard_lost);
    if (t->snaps || t->sink_put) {
        fprintf(stderr, "xtcg-cache: dir: refused %" PRIu64 " scans "
                "truncated %" PRIu64 " over budget: mapping %" PRIu64
                " disk %" PRIu64 "; unpublished after a partial scan %"
                PRIu64 "\n", t->snap_refused, t->scan_trunc,
                t->map_budget, t->publish_budget, t->publish_blind);
        fprintf(stderr, "xtcg-cache: dir: compactions %" PRIu64 " (failed %"
                PRIu64 ", at exit %" PRIu64 ", busy %" PRIu64 ") %.3f ms: %"
                PRIu64 " files, %" PRIu64 " artifacts read, %" PRIu64
                " kept, %" PRIu64 " aged out, %" PRIu64 " damaged, %" PRIu64
                " copies; %" PRIu64 " bytes; skipped %" PRIu64
                ", tables regrown %" PRIu64 ", collisions %" PRIu64
                "; removed %" PRIu64 " (failed %" PRIu64 ")\n",
                t->compactions, t->compact_fail, t->compact_exit,
                t->compact_busy, t->compact_ns / 1e6, t->compact_in,
                t->compact_arts, t->compact_kept, t->compact_aged,
                t->compact_damaged, t->compact_dups, t->compact_bytes,
                t->compact_skip, t->compact_regrow, t->compact_collide,
                t->removed, t->remove_fail);
        fprintf(stderr, "xtcg-cache: dir: merges");
        for (int k = 0; k < 4; k++) {
            static const char *const kn[4] = {
                "minor", "parts", "major", "first",
            };

            fprintf(stderr, " %s %" PRIu64 "/%" PRIu64 "/%" PRIu64
                    " (est %.1f act %.1f age %.1f ms, %" PRIu64 " KiB in, %"
                    PRIu64 " entries)",
                    kn[k], t->merge_done[k], t->merge_fail[k],
                    t->merge_exit[k], t->merge_est_ns[k] / 1e6,
                    t->merge_act_ns[k] / 1e6, t->merge_age_ns[k] / 1e6,
                    t->merge_in_bytes[k] >> 10, t->merge_entries[k]);
        }
        fprintf(stderr, "; deferred %" PRIu64 "; index refused: images %"
                PRIu64 " slots %" PRIu64 " probes %" PRIu64 " cancelled %"
                PRIu64, t->merge_deferred,
                t->merge_refused_index[TCG_CACHE_PLAN_IMG],
                t->merge_refused_index[TCG_CACHE_PLAN_SLOTS],
                t->merge_refused_index[TCG_CACHE_PLAN_PROBES],
                t->merge_refused_index[TCG_CACHE_PLAN_CANCEL]);
        fprintf(stderr, "; emergency %" PRIu64 ", saturated %" PRIu64
                ", written %" PRIu64 " KiB; parts %" PRIu64 " live %" PRIu64
                " unresolved %" PRIu64 " covered, overflows %" PRIu64
                "; loose %" PRIu64 "; scan retained %" PRIu64 " KiB\n",
                t->merge_emergency, t->merge_saturated,
                t->merge_tmp_bytes >> 10, t->parts_live,
                t->parts_unresolved, t->parts_covered, t->parts_overflow,
                t->scan_loose, t->scan_mem_max >> 10);
        fprintf(stderr, "xtcg-cache: dir: snapshots %" PRIu64 " (%" PRIu64
                " files, %" PRIu64 " skipped) start-up %.3f ms, snapshots"
                " %.3f ms; captured %" PRIu64 " (dropped %" PRIu64
                "), published %" PRIu64 " (failed %" PRIu64 ") %.3f ms, %"
                PRIu64 " bytes\n",
                t->snaps, t->snap_files, t->snap_skipped, t->startup_ns / 1e6,
                t->refresh_ns / 1e6, t->sink_put, t->sink_dropped,
                t->published, t->publish_fail, t->publish_ns / 1e6,
                t->publish_bytes);
    }
    if (t->file_lookups) {
        fprintf(stderr, "xtcg-cache: file: lookups %" PRIu64 " hits %"
                PRIu64 " rejected:", t->file_lookups, t->file_hits);
        for (int i = 1; i < TCG_CACHE_V_MAX; i++) {
            if (t->file_reject[i]) {
                fprintf(stderr, " %s=%" PRIu64, tcg_cache_v_name(i),
                        t->file_reject[i]);
            }
        }
        fprintf(stderr, "; copies skipped %" PRIu64 "; finds examined %"
                PRIu64 " slots (largest %" PRIu64 "); opens %" PRIu64
                " (%.3f ms, image records %" PRIu64 " bytes)\n", t->sel_dups,
                t->find_slots, t->find_slots_max, t->opens, t->open_ns / 1e6,
                t->open_img_bytes);
    }
    if (tcg_cache_pages) {
        tcg_cache_pages_print();
    }
    if (t->file_fail) {
        fprintf(stderr, "xtcg-cache: file: failed installs %" PRIu64
                " (%.3f ms); relocs", t->file_fail, t->file_fail_ns / 1e6);
        for (int i = 0; i < ARRAY_SIZE(kinds); i++) {
            if (t->inst_fail_rk[i]) {
                fprintf(stderr, " %s=%" PRIu64, kinds[i], t->inst_fail_rk[i]);
            }
        }
        fprintf(stderr, " |");
        for (int i = 0; i < ARRAY_SIZE(forms); i++) {
            if (t->inst_fail_rf[i]) {
                fprintf(stderr, " %s=%" PRIu64, forms[i], t->inst_fail_rf[i]);
            }
        }
        fprintf(stderr, "; key-pc=%" PRIu64 "\n", t->inst_fail_kpc);
    }
    if (t->file_lookups || t->gen[TCG_CACHE_W_NONE]) {
        fprintf(stderr, "xtcg-cache: file: translated after");
        for (int i = 0; i < TCG_CACHE_W_MAX; i++) {
            if (t->gen[i]) {
                fprintf(stderr, " %s=%" PRIu64 " (%.3f ms)", why[i],
                        t->gen[i], t->gen_ns[i] / 1e6);
            }
        }
        fprintf(stderr, "\n");
    }
    if (tcg_ctx->code_gen_buffer) {
        fprintf(stderr, "xtcg-cache: layout: code buffer %p+%zx anchor %"
                PRIxPTR "\n", tcg_ctx->code_gen_buffer,
                tcg_ctx->code_gen_buffer_size, tcg_cache_anchor());
    }
    fprintf(stderr, "xtcg-cache: on: ns lookup %.0f copy %.0f check %.0f"
            " hit %.0f (per lookup, per copy, per guest-byte check,"
            " per hit)\n",
            t->lookups ? (double)t->look_ns / t->lookups : 0,
            t->copies ? (double)t->copy_ns / t->copies : 0,
            t->checks ? (double)t->check_ns / t->checks : 0,
            t->hits ? (double)t->hit_ns / t->hits : 0);
    if (tcg_cache_costs) {
        /* What reading the clock costs, which each part's time includes. */
        int64_t c0 = get_clock();

        for (int i = 0; i < 10000; i++) {
            get_clock();
        }
        fprintf(stderr, "xtcg-cache: clock %.1f ns a reading\n",
                (get_clock() - c0) / 10000.0);
        fprintf(stderr, "xtcg-cache: cost: select %" PRIu64 " finds %.3f ms, %"
                PRIu64 " gets %.3f ms (%" PRIu64 " bytes), copies %.3f ms, %"
                PRIu64 " validations %.3f ms; install prep %.3f check %.3f"
                " reserve %.3f place %.3f flush %.3f link %.3f ms\n",
                t->sel_finds, t->sel_find_ns / 1e6, t->sel_gets,
                t->sel_get_ns / 1e6, t->sel_get_bytes, t->sel_dup_ns / 1e6,
                t->sel_vals, t->sel_val_ns / 1e6, t->inst_prep_ns / 1e6,
                t->check_ns / 1e6, t->inst_res_ns / 1e6,
                t->inst_place_ns / 1e6, t->inst_flush_ns / 1e6,
                t->inst_link_ns / 1e6);
    }
}
