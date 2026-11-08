/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Translation artifacts in files (tcg-cache.h): the envelope, segment and
 * pack formats, their bounded readers, and the validator an artifact read
 * from a file passes before anything in it is used.  Included at the end
 * of tcg.c, after tcg-cache.c.inc, for the back end's decode and zero.
 *
 * Files are untrusted: every read of a mapped file goes through the
 * guarded copy (a file may be truncated under its mapping), every fixed
 * header is copied out and checked before any offset in it is used, and
 * every count and length has a hard limit.  The validator checks that an
 * artifact is well formed; it can't check that its code does what its
 * guest bytes say, which the directory's ownership vouches for.
 */

#include "tcg/insn-start-words.h"

uint8_t tcg_cache_fingerprint[16];
bool (*tcg_cache_insn_ok)(const uint64_t *data, bool pcrel);
const uint64_t *tcg_cache_insn_bad;
int tcg_cache_insn_nbad;

/* XXH64 (Yann Collet's xxHash, 64-bit), for checksums and identities. */
#define XXH_P1 0x9E3779B185EBCA87ull
#define XXH_P2 0xC2B2AE3D27D4EB4Full
#define XXH_P3 0x165667B19E3779F9ull
#define XXH_P4 0x85EBCA77C2B2AE63ull
#define XXH_P5 0x27D4EB2F165667C5ull

static uint64_t xxh_round(uint64_t acc, uint64_t in)
{
    acc += in * XXH_P2;
    acc = rol64(acc, 31);
    return acc * XXH_P1;
}

static uint64_t xxh_merge(uint64_t acc, uint64_t v)
{
    acc ^= xxh_round(0, v);
    return acc * XXH_P1 + XXH_P4;
}

uint64_t tcg_cache_hash64(uint64_t seed, const void *data, size_t len)
{
    const uint8_t *p = data, *end = p + len;
    uint64_t h;

    if (len >= 32) {
        uint64_t v1 = seed + XXH_P1 + XXH_P2, v2 = seed + XXH_P2;
        uint64_t v3 = seed, v4 = seed - XXH_P1;

        do {
            v1 = xxh_round(v1, ldq_le_p(p));
            v2 = xxh_round(v2, ldq_le_p(p + 8));
            v3 = xxh_round(v3, ldq_le_p(p + 16));
            v4 = xxh_round(v4, ldq_le_p(p + 24));
            p += 32;
        } while (p + 32 <= end);
        h = rol64(v1, 1) + rol64(v2, 7) + rol64(v3, 12) + rol64(v4, 18);
        h = xxh_merge(h, v1);
        h = xxh_merge(h, v2);
        h = xxh_merge(h, v3);
        h = xxh_merge(h, v4);
    } else {
        h = seed + XXH_P5;
    }
    h += len;
    for (; p + 8 <= end; p += 8) {
        h ^= xxh_round(0, ldq_le_p(p));
        h = rol64(h, 27) * XXH_P1 + XXH_P4;
    }
    if (p + 4 <= end) {
        h ^= (uint64_t)ldl_le_p(p) * XXH_P1;
        h = rol64(h, 23) * XXH_P2 + XXH_P3;
        p += 4;
    }
    for (; p < end; p++) {
        h ^= *p * XXH_P5;
        h = rol64(h, 11) * XXH_P1;
    }
    h ^= h >> 33;
    h *= XXH_P2;
    h ^= h >> 29;
    h *= XXH_P3;
    return h ^ (h >> 32);
}

/* A key's hash in an index: never 0, which marks an empty pack slot. */
static uint64_t key_hash(uint64_t id, uint64_t rva, uint32_t flags,
                         uint64_t cs_base, uint32_t cflags)
{
    uint64_t k[4] = { id, rva, cs_base, (uint64_t)flags << 32 | cflags };
    uint64_t h = tcg_cache_hash64(0, k, sizeof(k));

    return h ? h : 1;
}

static uint32_t key_check(uint64_t rva, uint32_t flags)
{
    return (uint32_t)(rva ^ (rva >> 32)) ^ flags;
}

static const char *const tcg_cache_v_names[TCG_CACHE_V_MAX] = {
    [TCG_CACHE_V_OK] = "ok",
    [TCG_CACHE_V_HEADER] = "header",
    [TCG_CACHE_V_LIMIT] = "limit",
    [TCG_CACHE_V_SPAN] = "span",
    [TCG_CACHE_V_EXTENT] = "extent",
    [TCG_CACHE_V_REL_ORDER] = "rel-order",
    [TCG_CACHE_V_REL_FORM] = "rel-form",
    [TCG_CACHE_V_REL_SITE] = "rel-site",
    [TCG_CACHE_V_REL_CANON] = "rel-canon",
    [TCG_CACHE_V_REL_TARGET] = "rel-target",
    [TCG_CACHE_V_SLOT] = "slot",
    [TCG_CACHE_V_CON] = "constraint",
    [TCG_CACHE_V_UNWIND] = "unwind",
    [TCG_CACHE_V_LAZY] = "lazy",
    [TCG_CACHE_V_KEY] = "key",
    [TCG_CACHE_V_CHECK] = "checksum",
    [TCG_CACHE_V_FAULT] = "fault",
    [TCG_CACHE_V_INSN] = "insn-state",
};

const char *tcg_cache_v_name(int v)
{
    return v >= 0 && v < TCG_CACHE_V_MAX ? tcg_cache_v_names[v] : "?";
}

/* The validator. */

typedef struct ValParts {
    const uint8_t *hot, *cold;
    uint32_t hot_len, cold_len;
    uint32_t code_len;      /* the hot part's code, before its pool */
} ValParts;

#ifdef TCG_TARGET_HAS_CACHE
/*
 * A place where code executes: @need bytes of instructions in the hot
 * part's code (not its pool) or in the cold part.  Slot templates, reset
 * labels, trampolines and conditional branches must be such places.
 */
static const uint8_t *val_code(const ValParts *vp, uint32_t place,
                               uint32_t need)
{
    uint32_t off = place & ~TCG_CACHE_COLD_BIT;
    bool cold = place & TCG_CACHE_COLD_BIT;
    uint32_t len = cold ? vp->cold_len : vp->code_len;

    if ((off & 3) || need == 0 || off > len || need > len - off) {
        return NULL;
    }
    return (cold ? vp->cold : vp->hot) + off;
}

/*
 * A place's bytes: @need of them inside its part, or with @end, a place
 * up to the part's end itself (a label there; @need 0).
 */
static const uint8_t *val_place(const ValParts *vp, uint32_t place,
                                uint32_t need, bool end)
{
    uint32_t off = place & ~TCG_CACHE_COLD_BIT;
    bool cold = place & TCG_CACHE_COLD_BIT;
    uint32_t len = cold ? vp->cold_len : vp->hot_len;

    if (off > len || need > len - off || (!end && need == 0)) {
        return NULL;
    }
    return (cold ? vp->cold : vp->hot) + off;
}

/* The bytes a form patches. */
static uint32_t val_form_len(int form, uint16_t aux)
{
    switch (form) {
    case TCG_CAPF_B26:
    case TCG_CAPF_BCOND19:
    case TCG_CAPF_TBZ14:
    case TCG_CAPF_LDRLIT19:
    case TCG_CAPF_ADR21:
    case TCG_CAPF_ADRP:
    case TCG_CAPF_REL32:
        return 4;
    case TCG_CAPF_ADRP_ADD:
    case TCG_CAPF_ADRP_LDR:
    case TCG_CAPF_POOL64:
        return 8;
    case TCG_CAPF_MOVW:
        return 4 * ctpop32(aux & TCG_CAP_MOVW_MASK);
    default:
        return 0;
    }
}

static bool val_aux_ok(int form, uint16_t aux)
{
    if (form != TCG_CAPF_MOVW) {
        return aux == 0;
    }
    if (aux & ~(TCG_CAP_MOVW_MASK | TCG_CAP_MOVW_MOVN | TCG_CAP_MOVW_X)
        || !(aux & TCG_CAP_MOVW_MASK)) {
        return false;
    }
    return (aux & TCG_CAP_MOVW_X) || !(aux & TCG_CAP_MOVW_MASK & ~3);
}

#define VAL_NOP     0xd503201f
#define VAL_BR_X16  0xd61f0200
#define VAL_BTI_J   0xd503249f

static bool val_is_branch(uint32_t insn)
{
    return (insn & 0xfc000000) == 0x14000000 || insn == VAL_NOP;
}

/* A bounded signed LEB128, as encode_sleb128 writes it (64-bit). */
static bool val_sleb(const uint8_t **pp, const uint8_t *end, int64_t *out)
{
    const uint8_t *p = *pp;
    uint64_t val = 0;
    int byte, shift = 0;

    do {
        if (p == end || shift > 63) {
            return false;
        }
        byte = *p++;
        /* The tenth byte holds bit 63 alone: 0x00 or 0x7f, and ends it. */
        if (shift == 63 && byte != 0x00 && byte != 0x7f) {
            return false;
        }
        val |= (uint64_t)(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) {
        val |= -(uint64_t)1 << shift;
    }
    *pp = p;
    *out = val;
    return true;
}

#define VAL_MAX_LAZY_MAPS 4096

#ifdef CONFIG_USER_ONLY
/* A lazy-writeback record must name a global, with its type. */
static bool val_wb_global(TCGContext *s, unsigned base, int64_t ofs,
                          unsigned type)
{
    for (int i = 0; i < s->nb_globals; i++) {
        const TCGTemp *ts = &s->temps[i];

        if (ts->kind == TEMP_GLOBAL && ts->mem_base
            && ts->mem_base->kind == TEMP_FIXED
            && ts->mem_base->reg == base && ts->mem_offset == ofs
            && ts->type == type) {
            return true;
        }
    }
    return false;
}
#endif

/* The unwind rows, then (tcg_lazysync_user) the lazy-sync map. */
static int val_search(TCGContext *s, const TCGCacheArtView *v)
{
    const TCGCacheArt *h = v->h;
    const uint8_t *p = v->search, *end = p + h->search_len;
    int64_t x, host = 0;

    uint64_t data[INSN_START_WORDS] = { };

    if (!tcg_cache_insn_ok) {
        return TCG_CACHE_V_UNWIND;
    }
    if (!(h->cflags & CF_PCREL)) {
        data[0] = h->pc;
    }
    for (int i = 0; i < h->icount; i++) {
        /* Each row as cpu_unwind_data_from_tb rebuilds it, for the target. */
        for (int j = 0; j < INSN_START_WORDS; j++) {
            if (!val_sleb(&p, end, &x)) {
                return TCG_CACHE_V_UNWIND;
            }
            data[j] += x;
        }
        if (!tcg_cache_insn_ok(data, h->cflags & CF_PCREL)) {
            if (tcg_cache_debug) {
                fprintf(stderr, "insn-state: pc %" PRIx64 " row %d: %" PRIx64
                        " %" PRIx64 " %" PRIx64 "\n", h->pc, i, data[0],
                        data[1], data[2]);
            }
            return TCG_CACHE_V_INSN;
        }
        if (!val_sleb(&p, end, &x) || x < 0 || x > h->pool_off - host) {
            return TCG_CACHE_V_UNWIND;
        }
        host += x;
    }
#ifdef CONFIG_USER_ONLY
    if (tcg_lazysync_user) {
        int64_t n;

        if (!val_sleb(&p, end, &n) || n < 0 || n > VAL_MAX_LAZY_MAPS) {
            return TCG_CACHE_V_LAZY;
        }
        for (int64_t i = 0; i < n; i++) {
            int64_t start, len, nb_wb;

            if (!val_sleb(&p, end, &start) || !val_sleb(&p, end, &len)
                || !val_sleb(&p, end, &nb_wb) || start < 0 || len < 0
                || start > h->pool_off || len > h->pool_off - start
                || nb_wb < 0 || nb_wb > s->nb_globals) {
                return TCG_CACHE_V_LAZY;
            }
            for (int64_t j = 0; j < nb_wb; j++) {
                unsigned reg, base, type;
                int64_t ofs, val;
                bool is_const;

                if (end - p < 3) {
                    return TCG_CACHE_V_LAZY;
                }
                reg = p[0];
                base = p[1];
                type = p[2];
                p += 3;
                is_const = reg == TCG_CACHE_LAZY_WB_CONST;
                if (!val_sleb(&p, end, &ofs)
                    || (!is_const && reg >= TCG_TARGET_NB_REGS)
                    || base >= TCG_TARGET_NB_REGS
                    || (type != TCG_TYPE_I32 && type != TCG_TYPE_I64
                        && type != TCG_TYPE_V64 && type != TCG_TYPE_V128)
                    || (is_const && type != TCG_TYPE_I32
                        && type != TCG_TYPE_I64)
                    || !val_wb_global(s, base, ofs, type)) {
                    return TCG_CACHE_V_LAZY;
                }
                if (is_const && !val_sleb(&p, end, &val)) {
                    return TCG_CACHE_V_LAZY;
                }
            }
        }
    }
#endif
    return p == end ? TCG_CACHE_V_OK : TCG_CACHE_V_UNWIND;
}

int tcg_cache_validate(const void *art, size_t len)
{
    TCGContext *s = tcg_ctx;
    TCGCacheArtView v;
    const TCGCacheArt *h;
    ValParts vp;
    uintptr_t img_lo, img_hi;
    uint64_t page_off, span_last;
    uint32_t total = 0, prev_end = 0, slots_mask, con_need = 0, con_seen = 0;
    size_t tbsz;

    if (len > TCG_CACHE_ART_MAX || !tcg_cache_art_view(art, len, &v)) {
        return TCG_CACHE_V_HEADER;
    }
    h = v.h;
    if (h->pad[0] || h->pad[1] || h->pad[2] || h->pad1 || h->pad2
        || h->flags & ~(TCG_CACHE_ART_SPLIT | TCG_CACHE_ART_PAGE2)
        || h->loops > 1 || h->edge_end > 1 || h->chain_dead_in > 1
        || h->hot_len == 0 || (h->hot_len & 3) || (h->pool_off & 3)
        || (h->cold_len & 3)
        || (!(h->flags & TCG_CACHE_ART_SPLIT) && h->cold_len)) {
        return TCG_CACHE_V_HEADER;
    }
    if (h->n_ext == 0 || h->n_ext > TCG_CACHE_MAX_EXT
        || h->n_rel > TCG_CACHE_MAX_REL || h->n_con > TB_JMP_SLOTS
        || h->n_acq > TCG_CACHE_MAX_ACQ || h->icount == 0
        || h->icount > TCG_MAX_INSNS) {
        return TCG_CACHE_V_LIMIT;
    }
    tbsz = tb_struct_size(h->nb_slots);
    slots_mask = (1u << h->nb_slots) - 1;
    if ((h->jmp_call & ~(slots_mask | TB_JMP_RET_LANDING))
        || (h->jmp_cold & ~slots_mask) || (h->jmp_far & ~slots_mask)) {
        return TCG_CACHE_V_SLOT;
    }

    /* The span: within the head's page and the next. */
    page_off = h->pc & ~TARGET_PAGE_MASK;
    span_last = page_off + h->size - 1;
    if (h->size == 0 || span_last >= 2 * TARGET_PAGE_SIZE
        || (span_last >= TARGET_PAGE_SIZE)
           != !!(h->flags & TCG_CACHE_ART_PAGE2)) {
        return TCG_CACHE_V_SPAN;
    }

    /* Extents: sorted, apart, adding up, covering the first insn. */
    {
        bool head = false;

        for (int i = 0; i < h->n_ext; i++) {
            const TCGCacheArtExt *e = &v.ext[i];

            if (e->len == 0 || (i && e->off <= prev_end)
                || e->off + e->len > 2 * TARGET_PAGE_SIZE) {
                return TCG_CACHE_V_EXTENT;
            }
            head |= e->off <= page_off && page_off < e->off + e->len;
            prev_end = e->off + e->len;
            total += e->len;
        }
        if (!head || total != h->ext_bytes) {
            return TCG_CACHE_V_EXTENT;
        }
    }

    vp = (ValParts){ v.hot, v.cold, h->hot_len, h->cold_len, h->pool_off };
    tcg_cache_image(&img_lo, &img_hi);

    /* Relocations: sorted, apart, decoding as their forms, canonical. */
    {
        uint64_t last_end = 0;

        for (int i = 0; i < h->n_rel; i++) {
            const TCGCacheArtRel *r = &v.rel[i];
            uint32_t need = val_form_len(r->form, r->aux);
            uint64_t site = r->site, at;
            const uint8_t *p;
            uint8_t canon[16];
            uintptr_t dummy;
            uintptr_t res;

            if (need == 0 || !val_aux_ok(r->form, r->aux)) {
                return TCG_CACHE_V_REL_FORM;
            }
            at = (site & TCG_CACHE_COLD_BIT ? 1ull << 32 : 0)
                 + (site & ~TCG_CACHE_COLD_BIT);
            if (i && at < last_end) {
                return TCG_CACHE_V_REL_ORDER;
            }
            last_end = at + need;
            p = val_place(&vp, r->site, need, false);
            if (!p || (site & 3)
                || (r->form == TCG_CAPF_POOL64 && (site & 7))) {
                return TCG_CACHE_V_REL_SITE;
            }
            memcpy(canon, p, need);
            tcg_cache_zero(canon, r->form, r->aux);
            if (memcmp(canon, p, need)) {
                return TCG_CACHE_V_REL_CANON;
            }
            if (!tcg_cache_decode(p, 0, r->form, r->aux, &dummy)) {
                return TCG_CACHE_V_REL_FORM;
            }
            switch (r->kind) {
            case TCG_CAP_ABS:
                break;
            case TCG_CAP_HELPER:
                res = tcg_cache_anchor() + r->val;
                if (img_lo == img_hi || res < img_lo || res >= img_hi) {
                    return TCG_CACHE_V_REL_TARGET;
                }
                break;
            case TCG_CAP_STUB:
                if (r->val >= TCG_STUB_MAX) {
                    return TCG_CACHE_V_REL_TARGET;
                }
                break;
            case TCG_CAP_OWN_TB:
                if (r->val >= tbsz) {
                    return TCG_CACHE_V_REL_TARGET;
                }
                break;
            case TCG_CAP_THUNK:
                if (!(h->flags & TCG_CACHE_ART_SPLIT)) {
                    return TCG_CACHE_V_REL_TARGET;
                }
                break;
            case TCG_CAP_HOT:
                if (r->val > h->hot_len) {
                    return TCG_CACHE_V_REL_TARGET;
                }
                break;
            case TCG_CAP_COLD:
                if (r->val > h->cold_len) {
                    return TCG_CACHE_V_REL_TARGET;
                }
                break;
            default:
                return TCG_CACHE_V_REL_TARGET;
            }
        }
    }

    /*
     * Slots, by the templates the back end emits (tcg_out_goto_tb and its
     * variants), since linking and unlinking patch them in place:
     * - plain: B, then BR x16, the reset label right after (linking may
     *   make the B an LDR of target_addr: a constraint, below);
     * - next (cold, reset the next insn): a NOP;
     * - cold or call: B, and before the reset label a trampoline loading
     *   this slot's target_addr into x16 and branching to it, LDR literal
     *   or (jmp_far) ADRP and LDR, then BR x16.  A call slot always has
     *   one: an out-of-range link is a BL to it.
     * With BTI, every reset label after a BR is a landing pad.  A slot's
     * cond branch, which linking points at the same TB, lies in the same
     * part as the slot and branches to it.  dead names a live slot.
     */
    for (int n = 0; n < h->nb_slots; n++) {
        const TCGCacheArtSlot *sl = &v.slot[n];
        bool cold = h->jmp_cold & (1u << n), call = h->jmp_call & (1u << n);
        bool far_ = h->jmp_far & (1u << n), bti = (cpuinfo & CPUINFO_BTI)
                                                 && tcg_bti;
        const uint8_t *ip, *rp;
        uint32_t insn;
        bool tramp;

        if (sl->pad[0] || sl->pad[1] || sl->pad[2] || sl->dead > h->nb_slots
            || (sl->dead
                && v.slot[sl->dead - 1].insn == TB_JMP_OFFSET_INVALID)) {
            return TCG_CACHE_V_SLOT;
        }
        if (sl->insn == TB_JMP_OFFSET_INVALID) {
            if (sl->reset != TB_JMP_OFFSET_INVALID || sl->cond || cold
                || call || far_ || sl->dead) {
                return TCG_CACHE_V_SLOT;
            }
            continue;
        }
        ip = val_code(&vp, sl->insn, 4);
        rp = sl->reset == TB_JMP_OFFSET_INVALID
             ? NULL : val_code(&vp, sl->reset, 4);
        if (!ip || !rp || (sl->insn & 3) || (sl->reset & 3)
            || (!(cold || call)
                && (sl->insn & TCG_CACHE_COLD_BIT)
                   != (sl->reset & TCG_CACHE_COLD_BIT))) {
            return TCG_CACHE_V_SLOT;
        }
        insn = ldl_he_p(ip);
        if (!(cold || call)) {
            const uint8_t *br = val_code(&vp, sl->insn + 4, 4);

            if ((insn & 0xfc000000) != 0x14000000 || far_ || sl->cond
                || !br || ldl_he_p(br) != VAL_BR_X16
                || sl->reset != sl->insn + 8) {
                return TCG_CACHE_V_SLOT;
            }
            if (bti && ldl_he_p(rp) != VAL_BTI_J) {
                return TCG_CACHE_V_SLOT;
            }
            con_need |= 1u << n;
            continue;
        }
        tramp = sl->reset != sl->insn + 4;
        if (!tramp) {
            /* goto_tb_next: no trampoline, so not a call. */
            if (call || far_ || insn != VAL_NOP) {
                return TCG_CACHE_V_SLOT;
            }
        } else {
            uint32_t tsz = far_ ? 12 : 8;
            uint32_t toff = sl->reset - tsz;
            const uint8_t *tp;
            bool found = false;

            if ((insn & 0xfc000000) != 0x14000000
                || (sl->reset & ~TCG_CACHE_COLD_BIT) < tsz) {
                return TCG_CACHE_V_SLOT;
            }
            tp = val_code(&vp, toff, tsz);
            if (!tp) {
                return TCG_CACHE_V_SLOT;
            }
            if (far_ ? (ldl_he_p(tp) & 0x9f00001f) != 0x90000010
                      || (ldl_he_p(tp + 4) & 0xffc003ff) != 0xf9400210
                      || ldl_he_p(tp + 8) != VAL_BR_X16
                    : (ldl_he_p(tp) & 0xff00001f) != 0x58000010
                      || ldl_he_p(tp + 4) != VAL_BR_X16) {
                return TCG_CACHE_V_SLOT;
            }
            if (bti && ldl_he_p(rp) != VAL_BTI_J) {
                return TCG_CACHE_V_SLOT;
            }
            for (int i = 0; i < h->n_rel; i++) {
                found |= v.rel[i].site == toff
                         && v.rel[i].kind == TCG_CAP_OWN_TB
                         && v.rel[i].val
                            == offsetof(TranslationBlock, jmp)
                               + n * sizeof(struct TBJmpSlot)
                               + offsetof(struct TBJmpSlot, target_addr)
                         && v.rel[i].form
                            == (far_ ? TCG_CAPF_ADRP_LDR : TCG_CAPF_LDRLIT19);
            }
            if (!found) {
                return TCG_CACHE_V_SLOT;
            }
        }
        if (sl->cond) {
            uint32_t c = sl->cond - 1;
            const uint8_t *cp = val_code(&vp, c, 4);
            uintptr_t to;

            /* Decoded at its offset in the part, it must reach the slot. */
            if (call || !cp || (c & 3)
                || (c & TCG_CACHE_COLD_BIT) != (sl->insn & TCG_CACHE_COLD_BIT)
                || !tcg_cache_decode(cp, c & ~TCG_CACHE_COLD_BIT,
                                     TCG_CAPF_BCOND19, 0, &to)
                || to != (sl->insn & ~TCG_CACHE_COLD_BIT)) {
                return TCG_CACHE_V_SLOT;
            }
            for (int i = 0; i < h->n_rel; i++) {
                if (v.rel[i].site == c) {
                    return TCG_CACHE_V_SLOT;
                }
            }
        }
    }

    /* Constraints: exactly the plain slots, each at its patch site. */
    for (int i = 0; i < h->n_con; i++) {
        const TCGCacheArtCon *c = &v.con[i];

        if (c->kind != TCG_CAPC_SLOT_LDRLIT || c->pad
            || c->slot >= h->nb_slots || (con_seen & (1u << c->slot))
            || c->site != v.slot[c->slot].insn) {
            return TCG_CACHE_V_CON;
        }
        con_seen |= 1u << c->slot;
    }
    if (con_seen != con_need) {
        return TCG_CACHE_V_CON;
    }
    return val_search(s, &v);
}
#else
int tcg_cache_validate(const void *art, size_t len)
{
    return TCG_CACHE_V_HEADER;
}
#endif

/* Envelopes. */

static uint64_t env_content(const TCGCacheEnv *e, const void *art,
                            size_t len)
{
    uint64_t k[4] = { e->id, e->rva, e->cs_base,
                      (uint64_t)e->flags << 32 | e->cflags };

    return tcg_cache_hash64(tcg_cache_hash64(0, k, sizeof(k)), art, len);
}

static uint64_t env_check(const TCGCacheEnv *e, const void *art, size_t len)
{
    TCGCacheEnv c = *e;

    c.check = 0;
    return tcg_cache_hash64(tcg_cache_hash64(1, &c, sizeof(c)), art, len);
}

size_t tcg_cache_envelope(void *out, uint64_t id, uint64_t rva,
                          uint32_t born, const void *art, size_t len)
{
    const TCGCacheArt *h = art;
    TCGCacheEnv *e = out;

    *e = (TCGCacheEnv){
        .magic = TCG_CACHE_ENV_MAGIC, .len = sizeof(*e) + len, .born = born,
        .id = id, .rva = rva, .cs_base = h->cs_base, .flags = h->tb_flags,
        .cflags = h->cflags,
    };
    memcpy(e + 1, art, len);
    memset((uint8_t *)(e + 1) + len, 0,
           ROUND_UP(sizeof(*e) + len, 8) - sizeof(*e) - len);
    e->content = env_content(e, art, len);
    e->check = env_check(e, art, len);
    return ROUND_UP(sizeof(*e) + len, 8);
}

/* Files. */

static uint64_t hdr_check(const TCGCacheFileHdr *h)
{
    TCGCacheFileHdr c = *h;

    c.check = 0;
    return tcg_cache_hash64(2, &c, sizeof(c));
}

/* Copy @len bytes at @off of @f into @dst, guarded; false on a fault. */
static bool file_read(const TCGCacheFile *f, uint64_t off, void *dst,
                      size_t len)
{
    int64_t r;

    if (off > f->size || len > f->size - off) {
        return false;
    }
    r = f->copy((void *)dst, (const uint8_t *)f->map + off, len);
    if (r) {
        f->fault(r);
        return false;
    }
    return true;
}

/* "seg-" then [0-9a-z-] then ".xtc", NUL-terminated within the field. */
bool tcg_cache_segment_name_ok(const char name[64])
{
    size_t n = strnlen(name, 64);

    if (n == 64 || n < 9 || memcmp(name, "seg-", 4)
        || memcmp(name + n - 4, ".xtc", 4)) {
        return false;
    }
    for (size_t i = 4; i < n - 4; i++) {
        char c = name[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '-')) {
            return false;
        }
    }
    for (size_t i = n; i < 64; i++) {
        if (name[i]) {
            return false;
        }
    }
    return true;
}

int tcg_cache_file_open(TCGCacheFile *f, const void *map, size_t size,
                        int64_t (*copy)(void *, const void *, size_t),
                        void (*fault)(int64_t))
{
    TCGCacheFileHdr *h = &f->hdr;
    uint64_t data_end, index_bytes;

    memset(f, 0, sizeof(*f));
    f->map = map;
    f->size = size;
    f->copy = copy;
    f->fault = fault;
    if (size < sizeof(*h) || size > TCG_CACHE_FILE_MAX) {
        return TCG_CACHE_V_HEADER;
    }
    if (!file_read(f, 0, h, sizeof(*h))) {
        return TCG_CACHE_V_FAULT;
    }
    if ((h->magic != TCG_CACHE_SEG_MAGIC && h->magic != TCG_CACHE_PACK_MAGIC)
        || h->version != TCG_CACHE_FILE_VERSION || h->hdr_len != sizeof(*h)
        || hdr_check(h) != h->check) {
        return TCG_CACHE_V_HEADER;
    }
    if (memcmp(h->fp, tcg_cache_fingerprint, sizeof(h->fp))) {
        return TCG_CACHE_V_KEY;
    }
    if (h->magic == TCG_CACHE_PACK_MAGIC) {
        if (h->slot_log2 < 4 || h->slot_log2 > TCG_CACHE_SLOT_LOG2_MAX
            || h->n_index > (1u << (h->slot_log2 - 1))) {
            return TCG_CACHE_V_LIMIT;
        }
        index_bytes = (uint64_t)sizeof(TCGCacheIdx) << h->slot_log2;
    } else {
        if (h->slot_log2 || h->n_index > TCG_CACHE_SEG_ENTRIES_MAX) {
            return TCG_CACHE_V_LIMIT;
        }
        index_bytes = (uint64_t)sizeof(TCGCacheIdx) * h->n_index;
    }
    data_end = (uint64_t)h->data_off + h->data_len;
    if (h->index_off < sizeof(*h) || (h->index_off & 7)
        || h->index_off + index_bytes > size || (h->data_off & 7)
        || data_end > size || h->n_cover > TCG_CACHE_COVER_MAX
        || (h->magic == TCG_CACHE_SEG_MAGIC && h->n_cover)
        || (h->n_cover
            && ((uint64_t)h->cover_off + h->cover_len > size
                || h->cover_len
                   != (uint64_t)h->n_cover * sizeof(TCGCacheCover)))) {
        return TCG_CACHE_V_LIMIT;
    }
    if (h->n_cover) {
        size_t n = h->cover_len;
        void *buf = g_malloc(n);

        if (!file_read(f, h->cover_off, buf, n)) {
            g_free(buf);
            return TCG_CACHE_V_FAULT;
        }
        if (tcg_cache_hash64(3, buf, n) != h->cover_check) {
            g_free(buf);
            return TCG_CACHE_V_CHECK;
        }
        for (uint32_t i = 0; i < h->n_cover; i++) {
            if (!tcg_cache_segment_name_ok(((TCGCacheCover *)buf)[i].name)) {
                g_free(buf);
                return TCG_CACHE_V_HEADER;
            }
        }
        f->cover = buf;
    }
    f->index_bytes = index_bytes;
    return TCG_CACHE_V_OK;
}

void tcg_cache_file_close(TCGCacheFile *f)
{
    g_free(f->cover);
    f->cover = NULL;
}

/* Index entry @i, copied out and bounds-checked: why not, or 0. */
static int file_entry_r(const TCGCacheFile *f, uint32_t i, TCGCacheIdx *e)
{
    if (!file_read(f, f->hdr.index_off + (uint64_t)i * sizeof(*e), e,
                   sizeof(*e))) {
        return TCG_CACHE_V_FAULT;
    }
    if (e->khash == 0
        || (e->off >= f->hdr.data_off && e->len >= sizeof(TCGCacheEnv)
            && e->len <= sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX
            && (uint64_t)e->off + e->len
               <= (uint64_t)f->hdr.data_off + f->hdr.data_len)) {
        return TCG_CACHE_V_OK;
    }
    return TCG_CACHE_V_LIMIT;
}

static bool file_entry(const TCGCacheFile *f, uint32_t i, TCGCacheIdx *e)
{
    return file_entry_r(f, i, e) == TCG_CACHE_V_OK;
}

int tcg_cache_file_find(const TCGCacheFile *f, uint64_t id, uint64_t rva,
                        uint32_t flags, uint64_t cs_base, uint32_t cflags,
                        TCGCacheIdx *out, int max)
{
    uint64_t kh = key_hash(id, rva, flags, cs_base, cflags);
    uint32_t kc = key_check(rva, flags);
    TCGCacheIdx e;
    int n = 0;

    if (f->hdr.magic == TCG_CACHE_PACK_MAGIC) {
        uint32_t mask = (1u << f->hdr.slot_log2) - 1;

        for (uint32_t i = 0, k = kh & mask; i < TCG_CACHE_PROBES && n < max;
             i++, k = (k + 1) & mask) {
            if (!file_entry(f, k, &e)) {
                return n ? n : -1;
            }
            if (!e.khash) {
                break;
            }
            if (e.khash == kh && e.check == kc) {
                out[n++] = e;
            }
        }
        return n;
    }

    /* A segment: the first entry with the hash, by binary search. */
    {
        uint32_t lo = 0, hi = f->hdr.n_index;

        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;

            if (!file_entry(f, mid, &e)) {
                return -1;
            }
            if (e.khash < kh) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        for (uint32_t i = lo; i < f->hdr.n_index && n < max
             && i < lo + TCG_CACHE_PROBES; i++) {
            if (!file_entry(f, i, &e)) {
                return n ? n : -1;
            }
            if (e.khash != kh) {
                break;
            }
            if (e.check == kc) {
                out[n++] = e;
            }
        }
        return n;
    }
}

int tcg_cache_file_get(const TCGCacheFile *f, const TCGCacheIdx *e,
                       uint64_t id, uint64_t rva, uint32_t flags,
                       uint64_t cs_base, uint32_t cflags, void *buf,
                       size_t buf_size, const TCGCacheEnv **envp)
{
    TCGCacheEnv hdr;
    const TCGCacheEnv *env = buf;
    size_t alen;

    if (e->len > buf_size || !file_read(f, e->off, &hdr, sizeof(hdr))) {
        return TCG_CACHE_V_FAULT;
    }
    if (hdr.magic != TCG_CACHE_ENV_MAGIC || hdr.len != e->len) {
        return TCG_CACHE_V_HEADER;
    }
    if (hdr.id != id || hdr.rva != rva || hdr.flags != flags
        || hdr.cs_base != cs_base || hdr.cflags != cflags) {
        return TCG_CACHE_V_KEY;
    }
    if (!file_read(f, e->off, buf, e->len)) {
        return TCG_CACHE_V_FAULT;
    }
    alen = env->len - sizeof(*env);
    if (memcmp(env, &hdr, sizeof(hdr))
        || env_check(env, env + 1, alen) != env->check
        || env_content(env, env + 1, alen) != env->content) {
        return TCG_CACHE_V_CHECK;
    }
    /* The artifact's own key agrees with its envelope's. */
    if (env->pad || alen < sizeof(TCGCacheArt)
        || ((const TCGCacheArt *)(env + 1))->tb_flags != env->flags
        || ((const TCGCacheArt *)(env + 1))->cflags != env->cflags
        || ((const TCGCacheArt *)(env + 1))->cs_base != env->cs_base) {
        return TCG_CACHE_V_KEY;
    }
    *envp = env;
    return TCG_CACHE_V_OK;
}

/* Candidates already passed, across the files of one lookup. */
typedef struct SelSeen {
    void *env[TCG_CACHE_CANDS];
    int n;
} SelSeen;

/* One file's candidates for a key; true if @use stopped the lookup. */
static bool file_select(const TCGCacheFile *f, uint64_t id, uint64_t rva,
                        uint32_t flags, uint64_t cs_base, uint32_t cflags,
                        void *buf, size_t bufsz,
                        bool (*use)(const TCGCacheEnv *env, void *opaque),
                        void *opaque, uint64_t *rejects, SelSeen *seen)
{
    TCGCacheIdx fe[TCG_CACHE_PROBES];
    int fn;

    fn = tcg_cache_file_find(f, id, rva, flags, cs_base, cflags, fe,
                             TCG_CACHE_PROBES);
    if (fn < 0 && rejects) {
        rejects[TCG_CACHE_V_LIMIT]++;
    }
    for (int i = 0; i < fn && seen->n < TCG_CACHE_CANDS; i++) {
        const TCGCacheEnv *env;
        bool dup = false;
        int r;

        r = tcg_cache_file_get(f, &fe[i], id, rva, flags, cs_base, cflags,
                               buf, bufsz, &env);
        if (r == TCG_CACHE_V_KEY) {
            continue;
        }
        if (!r) {
            for (int k = 0; k < seen->n && !dup; k++) {
                const TCGCacheEnv *o = seen->env[k];

                dup = o->content == env->content && o->len == env->len
                      && !memcmp(o + 1, env + 1, env->len - sizeof(*env));
            }
            if (dup) {
                continue;
            }
            r = tcg_cache_validate(env + 1, env->len - sizeof(*env));
        }
        if (r) {
            if (rejects) {
                rejects[r]++;
            }
            continue;
        }
        seen->env[seen->n++] = g_memdup2(env, env->len);
        if (use(env, opaque)) {
            return true;
        }
    }
    return false;
}

static void sel_seen_free(SelSeen *seen)
{
    for (int k = 0; k < seen->n; k++) {
        g_free(seen->env[k]);
    }
}

/*
 * The candidates for a key, in index order, each passed to @use until it
 * returns true: distinct artifacts whose full key matches, at most
 * TCG_CACHE_CANDS, already validated.  Index entries whose envelope has
 * another key, or a copy of one already passed (the same content, its
 * bytes compared), don't count.  @buf holds the one being passed.  The
 * number passed.
 */
int tcg_cache_file_select(const TCGCacheFile *f, uint64_t id, uint64_t rva,
                          uint32_t flags, uint64_t cs_base, uint32_t cflags,
                          void *buf, size_t bufsz,
                          bool (*use)(const TCGCacheEnv *env, void *opaque),
                          void *opaque, uint64_t *rejects)
{
    SelSeen seen = { };
    int n;

    file_select(f, id, rva, flags, cs_base, cflags, buf, bufsz, use, opaque,
                rejects, &seen);
    n = seen.n;
    sel_seen_free(&seen);
    return n;
}

/* The same over a snapshot's files, in order, with one budget. */
int tcg_cache_snap_select(const TCGCacheSnap *snap, uint64_t id, uint64_t rva,
                          uint32_t flags, uint64_t cs_base, uint32_t cflags,
                          void *buf, size_t bufsz,
                          bool (*use)(const TCGCacheEnv *env, void *opaque),
                          void *opaque, uint64_t *rejects)
{
    SelSeen seen = { };
    int n;

    for (int i = 0; i < snap->n && seen.n < TCG_CACHE_CANDS; i++) {
        if (file_select(&snap->f[i], id, rva, flags, cs_base, cflags, buf,
                        bufsz, use, opaque, rejects, &seen)) {
            break;
        }
    }
    n = seen.n;
    sel_seen_free(&seen);
    return n;
}

/*
 * The snapshot lookups read (TCGCacheSnap), published by RCU: a back end
 * replaces it, and the old one is released after a grace period, so a
 * reader keeps its views mapped while it copies.  At most one released
 * snapshot waits: until it goes, tcg_cache_snap_publish refuses.
 */
TCGCacheSnap *tcg_cache_snap;
static bool snap_retired;
bool tcg_cache_file_missed;
uint32_t tcg_cache_born;

unsigned tcg_cache_retire_pause_ms;

static void snap_free(TCGCacheSnap *s)
{
    if (tcg_cache_retire_pause_ms) {
        g_usleep(tcg_cache_retire_pause_ms * 1000);
    }
    for (int i = 0; i < s->n; i++) {
        tcg_cache_file_close(&s->f[i]);
    }
    if (s->release) {
        s->release(s);
    }
    g_free(s);
    qatomic_set(&snap_retired, false);
}

bool tcg_cache_snap_publish(TCGCacheSnap *s)
{
    TCGCacheSnap *old;

    if (qatomic_read(&snap_retired)) {
        return false;
    }
    old = qatomic_xchg(&tcg_cache_snap, s);
    if (old) {
        qatomic_set(&snap_retired, true);
        call_rcu(old, snap_free, rcu);
    }
    return true;
}

bool tcg_cache_snap_waiting(void)
{
    return qatomic_read(&snap_retired);
}

/*
 * A fork's child: a snapshot being retired belongs to the parent's RCU
 * thread, which the child doesn't have; its callback may run in the
 * child's new one or not at all.  Nothing in the child uses it (lookups
 * read the current snapshot) and the child never publishes, so it is
 * forgotten: at worst its mappings stay.
 */
void tcg_cache_snap_fork_child(void)
{
    qatomic_set(&snap_retired, false);
}

/*
 * The sink: captured artifacts, as envelopes, in a queue of buffers the
 * back end's writer publishes.  A buffer is free, filling (the producer's,
 * at most one), queued (full, or handed over), or being written.  All of
 * it under sink_lock, held only to copy.  With no free buffer, captures
 * are dropped and counted.
 */
enum { BUF_FREE, BUF_FILLING, BUF_QUEUED, BUF_WRITING };

typedef struct SinkBuf {
    uint8_t *data;
    size_t len;
    int64_t first_ns;
    int state;
} SinkBuf;

bool tcg_cache_sink_on;
void (*tcg_cache_sink_wake)(void);
unsigned tcg_cache_sink_pause_ms;
static QemuMutex sink_lock;
static SinkBuf sink[TCG_CACHE_BUFS];
static int sink_cur = -1;

void tcg_cache_sink_init(void)
{
    qemu_mutex_init(&sink_lock);
    for (int i = 0; i < TCG_CACHE_BUFS; i++) {
        sink[i] = (SinkBuf){ .data = g_malloc(TCG_CACHE_BUF_SIZE) };
    }
    sink_cur = -1;
    qatomic_set(&tcg_cache_sink_on, true);
}

static int sink_free_buf(void)
{
    for (int i = 0; i < TCG_CACHE_BUFS; i++) {
        if (sink[i].state == BUF_FREE) {
            return i;
        }
    }
    return -1;
}

void tcg_cache_sink_put(uint64_t id, uint64_t rva, uint32_t born,
                        const void *art, size_t len, int64_t now)
{
    size_t need = ROUND_UP(sizeof(TCGCacheEnv) + len, 8);
    bool queued = false;

    if (!qatomic_read(&tcg_cache_sink_on) || need > TCG_CACHE_BUF_SIZE) {
        tcg_cache_stats.sink_dropped++;
        return;
    }
    if (tcg_cache_sink_pause_ms) {
        g_usleep(tcg_cache_sink_pause_ms * 1000);
    }
    qemu_mutex_lock(&sink_lock);
    /* Closed meanwhile (an exit): nothing more is taken. */
    if (!qatomic_read(&tcg_cache_sink_on)) {
        qemu_mutex_unlock(&sink_lock);
        tcg_cache_stats.sink_dropped++;
        return;
    }
    if (sink_cur >= 0 && sink[sink_cur].len + need > TCG_CACHE_BUF_SIZE) {
        sink[sink_cur].state = BUF_QUEUED;
        sink_cur = -1;
        queued = true;
    }
    if (sink_cur < 0) {
        sink_cur = sink_free_buf();
        if (sink_cur >= 0) {
            sink[sink_cur].state = BUF_FILLING;
            sink[sink_cur].len = 0;
            sink[sink_cur].first_ns = now;
        }
    }
    if (sink_cur < 0) {
        qemu_mutex_unlock(&sink_lock);
        tcg_cache_stats.sink_dropped++;
        if (queued && tcg_cache_sink_wake) {
            tcg_cache_sink_wake();
        }
        return;
    }
    sink[sink_cur].len += tcg_cache_envelope(sink[sink_cur].data
                                             + sink[sink_cur].len, id, rva,
                                             born, art, len);
    tcg_cache_stats.sink_put++;
    qemu_mutex_unlock(&sink_lock);
    if (queued && tcg_cache_sink_wake) {
        tcg_cache_sink_wake();
    }
}

/*
 * For the writer: a queued buffer, or the filling one if it is older
 * than @age_ns or @force; NULL if none.  It is the caller's until
 * tcg_cache_sink_give.  @trylock: give up if the lock is busy.
 */
void *tcg_cache_sink_take(int64_t now, int64_t age_ns, bool force,
                          bool trylock, size_t *lenp)
{
    void *d = NULL;

    if (trylock ? qemu_mutex_trylock(&sink_lock)
                : (qemu_mutex_lock(&sink_lock), 0)) {
        return NULL;
    }
    for (int i = 0; i < TCG_CACHE_BUFS && !d; i++) {
        if (sink[i].state == BUF_QUEUED) {
            sink[i].state = BUF_WRITING;
            d = sink[i].data;
            *lenp = sink[i].len;
        }
    }
    if (!d && sink_cur >= 0 && sink[sink_cur].len
        && (force || now - sink[sink_cur].first_ns >= age_ns)) {
        sink[sink_cur].state = BUF_WRITING;
        d = sink[sink_cur].data;
        *lenp = sink[sink_cur].len;
        sink_cur = -1;
    }
    qemu_mutex_unlock(&sink_lock);
    return d;
}

/* Testing: hold the sink's lock for @ms. */
void tcg_cache_sink_hold(unsigned ms)
{
    qemu_mutex_lock(&sink_lock);
    g_usleep(ms * 1000);
    qemu_mutex_unlock(&sink_lock);
}

void tcg_cache_sink_give(void *data)
{
    qemu_mutex_lock(&sink_lock);
    for (int i = 0; i < TCG_CACHE_BUFS; i++) {
        if (sink[i].data == data) {
            sink[i].state = BUF_FREE;
            sink[i].len = 0;
        }
    }
    qemu_mutex_unlock(&sink_lock);
}

/*
 * A clean exit: stop taking captures and claim every buffer with data,
 * at most TCG_CACHE_BUFS, without waiting for the lock (if it is busy,
 * nothing).  The claimed buffers are the caller's, never given back.
 */
int tcg_cache_sink_close(void **data, size_t *lens)
{
    int n = 0;

    if (!qatomic_read(&tcg_cache_sink_on) || qemu_mutex_trylock(&sink_lock)) {
        return 0;
    }
    qatomic_set(&tcg_cache_sink_on, false);
    for (int i = 0; i < TCG_CACHE_BUFS; i++) {
        if ((sink[i].state == BUF_QUEUED || sink[i].state == BUF_FILLING)
            && sink[i].len) {
            sink[i].state = BUF_WRITING;
            data[n] = sink[i].data;
            lens[n++] = sink[i].len;
        }
    }
    sink_cur = -1;
    qemu_mutex_unlock(&sink_lock);
    return n;
}

/* fork: the lock held across it; a child drops every buffer, and stops. */
void tcg_cache_sink_fork_start(void)
{
    if (sink[0].data) {
        qemu_mutex_lock(&sink_lock);
    }
}

void tcg_cache_sink_fork_end(bool child)
{
    if (!sink[0].data) {
        return;
    }
    if (child) {
        qemu_mutex_init(&sink_lock);
        for (int i = 0; i < TCG_CACHE_BUFS; i++) {
            sink[i].state = BUF_FREE;
            sink[i].len = 0;
        }
        sink_cur = -1;
        qatomic_set(&tcg_cache_sink_on, false);
    } else {
        qemu_mutex_unlock(&sink_lock);
    }
}

/* Writers, from a list of envelopes (each 8-aligned in @data). */

static int idx_cmp(const void *a, const void *b)
{
    const TCGCacheIdx *x = a, *y = b;

    return x->khash < y->khash ? -1 : x->khash > y->khash;
}

static TCGCacheIdx env_idx(const TCGCacheEnv *e, uint32_t off)
{
    return (TCGCacheIdx){
        .khash = key_hash(e->id, e->rva, e->flags, e->cs_base, e->cflags),
        .off = off, .len = e->len, .check = key_check(e->rva, e->flags),
    };
}

void *tcg_cache_write_file(bool pack, uint64_t tick, const void *data,
                           size_t data_len, const TCGCacheCover *cover,
                           uint32_t n_cover, size_t *lenp)
{
    TCGCacheFileHdr h = {
        .magic = pack ? TCG_CACHE_PACK_MAGIC : TCG_CACHE_SEG_MAGIC,
        .version = TCG_CACHE_FILE_VERSION, .hdr_len = sizeof(h),
        .tick = tick,
    };
    uint32_t n = 0, slots;
    size_t index_bytes, at, out_len;
    uint8_t *out;
    TCGCacheIdx *idx;

    /* Envelopes as a reader would take them, back to back. */
    for (size_t o = 0; o < data_len;) {
        const TCGCacheEnv *e = (const void *)((const uint8_t *)data + o);

        if (data_len - o < sizeof(*e) || e->magic != TCG_CACHE_ENV_MAGIC
            || e->len < sizeof(*e)
            || e->len > sizeof(*e) + TCG_CACHE_ART_MAX
            || ROUND_UP(e->len, 8) > data_len - o) {
            return NULL;
        }
        n++;
        o += ROUND_UP(e->len, 8);
    }
    /* Nothing a reader would refuse. */
    if ((!pack && n_cover)
        || n > TCG_CACHE_SEG_ENTRIES_MAX || n_cover > TCG_CACHE_COVER_MAX
        || data_len > TCG_CACHE_FILE_MAX
        || (pack && 2ull * n > 1ull << TCG_CACHE_SLOT_LOG2_MAX)) {
        return NULL;
    }
    memcpy(h.fp, tcg_cache_fingerprint, sizeof(h.fp));
    if (pack) {
        h.slot_log2 = 4;
        while ((1u << h.slot_log2) < 2 * n) {
            h.slot_log2++;
        }
        slots = 1u << h.slot_log2;
    } else {
        slots = n;
    }
    index_bytes = (size_t)slots * sizeof(TCGCacheIdx);
    h.n_index = n;
    h.index_off = sizeof(h);
    h.n_cover = n_cover;
    h.cover_off = h.index_off + index_bytes;
    h.cover_len = n_cover * sizeof(TCGCacheCover);
    h.data_off = ROUND_UP(h.cover_off + h.cover_len, 8);
    h.data_len = data_len;
    out_len = h.data_off + data_len;
    if (out_len > TCG_CACHE_FILE_MAX) {
        return NULL;
    }
    out = g_malloc0(out_len);
    idx = (TCGCacheIdx *)(out + h.index_off);
    at = 0;
    for (size_t o = 0; o < data_len;) {
        const TCGCacheEnv *e = (const void *)((const uint8_t *)data + o);
        TCGCacheIdx x = env_idx(e, h.data_off + o);

        if (pack) {
            uint32_t k = x.khash & (slots - 1);

            while (idx[k].khash) {
                k = (k + 1) & (slots - 1);
            }
            idx[k] = x;
        } else {
            idx[at++] = x;
        }
        o += ROUND_UP(e->len, 8);
    }
    if (!pack) {
        qsort(idx, n, sizeof(*idx), idx_cmp);
    }
    if (n_cover) {
        memcpy(out + h.cover_off, cover, h.cover_len);
        h.cover_check = tcg_cache_hash64(3, cover, h.cover_len);
    }
    memcpy(out + h.data_off, data, data_len);
    h.check = hdr_check(&h);
    memcpy(out, &h, sizeof(h));
    *lenp = out_len;
    return out;
}

/*
 * Testing (XTCG_CACHE_CHECKFILE): read every artifact of a file and
 * validate it; counts by outcome on stderr; the number not ok.
 */
static int check_one(const TCGCacheFile *f, const TCGCacheIdx *e,
                     void *buf, size_t bufsz)
{
    TCGCacheEnv hdr;
    const TCGCacheEnv *env;
    int r;

    if (!file_read(f, e->off, &hdr, sizeof(hdr))) {
        return TCG_CACHE_V_FAULT;
    }
    r = tcg_cache_file_get(f, e, hdr.id, hdr.rva, hdr.flags, hdr.cs_base,
                           hdr.cflags, buf, bufsz, &env);
    if (r) {
        return r;
    }
    return tcg_cache_validate(env + 1, env->len - sizeof(*env));
}

int tcg_cache_check_file(const void *map, size_t size, bool quiet,
                         uint64_t *counts)
{
    TCGCacheFile f;
    uint64_t local[TCG_CACHE_V_MAX] = { };
    uint64_t *c = counts ? counts : local;
    void *buf = g_malloc(sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX);
    uint32_t n;
    int r, bad = 0;

    r = tcg_cache_file_open(&f, map, size, tcg_cache_gcopy, tcg_cache_nofault);
    if (r) {
        c[r]++;
        g_free(buf);
        if (!quiet) {
            fprintf(stderr, "xtcg-cache check: file: %s\n",
                    tcg_cache_v_name(r));
        }
        return 1;
    }
    n = f.hdr.magic == TCG_CACHE_PACK_MAGIC ? 1u << f.hdr.slot_log2
                                             : f.hdr.n_index;
    for (uint32_t i = 0; i < n; i++) {
        TCGCacheIdx e;

        r = file_entry_r(&f, i, &e);
        if (r) {
            c[r]++;
            bad++;
            continue;
        }
        if (!e.khash) {
            continue;
        }
        r = check_one(&f, &e, buf, sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX);
        c[r]++;
        bad += r != 0;
    }
    if (!quiet) {
        fprintf(stderr, "xtcg-cache check: %s, %u entries:",
                f.hdr.magic == TCG_CACHE_PACK_MAGIC ? "pack" : "segment",
                f.hdr.n_index);
        for (int i = 0; i < TCG_CACHE_V_MAX; i++) {
            if (c[i]) {
                fprintf(stderr, " %s=%" PRIu64, tcg_cache_v_name(i), c[i]);
            }
        }
        fprintf(stderr, "\n");
    }
    tcg_cache_file_close(&f);
    g_free(buf);
    return bad;
}

void tcg_cache_nofault(int64_t code)
{
}

#ifdef TCG_TARGET_HAS_CACHE
/*
 * Testing (XTCG_CACHE_FUZZ): damage a valid file and its artifacts in
 * every way the readers must survive, and count what each check caught.
 * Returns the number of failures: a damaged artifact accepted, or
 * rejected by another check than the one the case is about.  A crash or
 * hang is a failure too, by not returning.  The targeted and random
 * damage is to an artifact copied out of its envelope, validated
 * directly; the file-level damage goes through the whole reader.
 */

/* An artifact's mutable view, in a copy. */
typedef struct FuzzArt {
    uint8_t *b;
    size_t len;
    TCGCacheArtView v;
    TCGCacheArt *h;
    TCGCacheArtSlot *slot;
    TCGCacheArtRel *rel;
    TCGCacheArtCon *con;
    TCGCacheArtExt *ext;
    uint8_t *hot, *cold, *search;
} FuzzArt;

static bool fuzz_view(FuzzArt *a)
{
    if (!tcg_cache_art_view(a->b, a->len, &a->v)) {
        return false;
    }
    a->h = (TCGCacheArt *)a->v.h;
    a->slot = (TCGCacheArtSlot *)a->v.slot;
    a->rel = (TCGCacheArtRel *)a->v.rel;
    a->con = (TCGCacheArtCon *)a->v.con;
    a->ext = (TCGCacheArtExt *)a->v.ext;
    a->hot = (uint8_t *)a->v.hot;
    a->cold = (uint8_t *)a->v.cold;
    a->search = (uint8_t *)a->v.search;
    return true;
}

/* A place's bytes in the copy (no checks: the place came from it). */
static uint8_t *fuzz_at(FuzzArt *a, uint32_t place)
{
    return place & TCG_CACHE_COLD_BIT
           ? a->cold + (place & ~TCG_CACHE_COLD_BIT) : a->hot + place;
}

/* Replace @len bytes at @off of the copy with @n bytes of @with. */
static void fuzz_splice(FuzzArt *a, size_t off, size_t len, const void *with,
                        size_t n)
{
    size_t nl = a->len - len + n;
    uint8_t *b = g_malloc(nl);

    memcpy(b, a->b, off);
    if (n) {
        memcpy(b + off, with, n);
    }
    memcpy(b + off + n, a->b + off + len, a->len - off - len);
    g_free(a->b);
    a->b = b;
    a->len = nl;
    ((TCGCacheArt *)b)->len = nl;
}

static uint8_t *fuzz_sleb_enc(uint8_t *p, int64_t val)
{
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0)
                 || (val == -1 && (byte & 0x40) != 0));
        *p++ = byte | (more ? 0x80 : 0);
    } while (more);
    return p;
}

/*
 * The unwind rows' deltas: @set changes row 0's column @col to @val, and
 * the rows are encoded again in front of the rest (the lazy-sync map).
 */
static bool fuzz_rows_set(FuzzArt *a, int col, int64_t val)
{
    const uint8_t *p = a->search, *end = p + a->h->search_len;
    size_t n = a->h->icount * (INSN_START_WORDS + 1), soff;
    int64_t *d = g_new(int64_t, n);
    uint8_t *enc, *q;
    bool ok = true;

    for (size_t i = 0; i < n && ok; i++) {
        ok = val_sleb(&p, end, &d[i]);
    }
    if (!ok) {
        g_free(d);
        return false;
    }
    d[col] = val;
    enc = g_malloc(n * 10 + (end - p) + 8);
    q = enc;
    for (size_t i = 0; i < n; i++) {
        q = fuzz_sleb_enc(q, d[i]);
    }
    memcpy(q, p, end - p);
    q += end - p;
    soff = a->search - a->b;
    {
        size_t nlen = q - enc, pad = ROUND_UP(nlen, 8) - nlen;

        memset(q, 0, pad);
        fuzz_splice(a, soff, a->len - soff, enc, nlen + pad);
        ((TCGCacheArt *)a->b)->search_len = nlen;
    }
    g_free(d);
    g_free(enc);
    return fuzz_view(a);
}

/* The first lazy-writeback record: its reg, base, type bytes. */
static uint8_t *fuzz_first_wb(FuzzArt *a)
{
#ifdef CONFIG_USER_ONLY
    const uint8_t *p = a->search, *end = p + a->h->search_len;
    int64_t x, nm;

    if (!tcg_lazysync_user) {
        return NULL;
    }
    for (int i = 0; i < a->h->icount * (INSN_START_WORDS + 1); i++) {
        if (!val_sleb(&p, end, &x)) {
            return NULL;
        }
    }
    if (!val_sleb(&p, end, &nm)) {
        return NULL;
    }
    for (int64_t i = 0; i < nm; i++) {
        int64_t st, ln, nwb;

        if (!val_sleb(&p, end, &st) || !val_sleb(&p, end, &ln)
            || !val_sleb(&p, end, &nwb)) {
            return NULL;
        }
        if (nwb > 0) {
            return (uint8_t *)p;
        }
    }
#endif
    return NULL;
}

/* A targeted damage: false if it doesn't apply to this artifact. */
typedef bool (*FuzzRule)(FuzzArt *a, uint64_t r);

static bool fr_no_ext(FuzzArt *a, uint64_t r)
{
    a->h->n_ext = 0;
    return true;
}

static bool fr_ext_order(FuzzArt *a, uint64_t r)
{
    TCGCacheArtExt t;

    if (a->h->n_ext < 2) {
        return false;
    }
    t = a->ext[0];
    a->ext[0] = a->ext[1];
    a->ext[1] = t;
    return true;
}

static bool fr_ext_touch(FuzzArt *a, uint64_t r)
{
    if (a->h->n_ext < 2) {
        return false;
    }
    a->ext[1].off = a->ext[0].off + a->ext[0].len;
    return true;
}

static bool fr_ext_short(FuzzArt *a, uint64_t r)
{
    if (a->ext[0].len < 2) {
        return false;
    }
    a->ext[0].len--;
    return true;
}

static bool fr_ext_far(FuzzArt *a, uint64_t r)
{
    TCGCacheArtExt *e = &a->ext[a->h->n_ext - 1];

    /* Its last byte past the second page. */
    e->off = 2 * TARGET_PAGE_SIZE - e->len + 1;
    return true;
}

static bool fr_ext_head(FuzzArt *a, uint64_t r)
{
    uint32_t po = a->h->pc & ~TARGET_PAGE_MASK;

    if (a->h->n_ext != 1 || a->ext[0].off != po || a->ext[0].len < 2
        || po + 1 + a->ext[0].len > 2 * TARGET_PAGE_SIZE) {
        return false;
    }
    a->ext[0].off = po + 1;
    return true;
}

static bool fr_size0(FuzzArt *a, uint64_t r)
{
    a->h->size = 0;
    return true;
}

static bool fr_page2(FuzzArt *a, uint64_t r)
{
    a->h->flags ^= TCG_CACHE_ART_PAGE2;
    return true;
}

static bool fr_icount0(FuzzArt *a, uint64_t r)
{
    a->h->icount = 0;
    return true;
}

static bool fr_flags(FuzzArt *a, uint64_t r)
{
    a->h->flags |= 0x80;
    return true;
}

static bool fr_pad(FuzzArt *a, uint64_t r)
{
    a->h->pad1 = 1;
    return true;
}

static bool fr_split_cold(FuzzArt *a, uint64_t r)
{
    if (!(a->h->flags & TCG_CACHE_ART_SPLIT) || !a->h->cold_len) {
        return false;
    }
    a->h->flags &= ~TCG_CACHE_ART_SPLIT;
    return true;
}

#define FUZZ_REL(r_) (&a->rel[(r_) % a->h->n_rel])

/* The last relocation, so that the order check can't come first. */
static bool fr_rel_misalign(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_rel) {
        return false;
    }
    a->rel[a->h->n_rel - 1].site += 2;
    return true;
}

static bool fr_rel_form(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_rel) {
        return false;
    }
    (FUZZ_REL(r))->form = TCG_CAPF_MAX + (r & 3);
    return true;
}

static bool fr_rel_raw(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_rel) {
        return false;
    }
    (FUZZ_REL(r))->form = TCG_CAPF_RAW_ADRP;
    return true;
}

static bool fr_rel_aux(FuzzArt *a, uint64_t r)
{
    TCGCacheArtRel *x;

    if (!a->h->n_rel) {
        return false;
    }
    x = FUZZ_REL(r);
    x->aux = x->form == TCG_CAPF_MOVW ? x->aux | 0x40 : 1;
    return true;
}

static bool fr_rel_out(FuzzArt *a, uint64_t r)
{
    TCGCacheArtRel *x;

    if (!a->h->n_rel) {
        return false;
    }
    x = &a->rel[a->h->n_rel - 1];
    x->site = (x->site & TCG_CACHE_COLD_BIT)
              | ((x->site & TCG_CACHE_COLD_BIT) ? a->h->cold_len
                                                : a->h->hot_len);
    return true;
}

static bool fr_rel_canon(FuzzArt *a, uint64_t r)
{
    TCGCacheArtRel *x;
    uint8_t *p;

    if (!a->h->n_rel) {
        return false;
    }
    x = FUZZ_REL(r);
    p = fuzz_at(a, x->site);
    switch (x->form) {
    case TCG_CAPF_POOL64:
    case TCG_CAPF_REL32:
    case TCG_CAPF_B26:
        p[0] ^= 1;
        break;
    default:
        /* Bit 5: inside every other form's field. */
        p[0] ^= 0x20;
        break;
    }
    return true;
}

static bool fr_rel_order(FuzzArt *a, uint64_t r)
{
    TCGCacheArtRel t;

    if (a->h->n_rel < 2) {
        return false;
    }
    t = a->rel[0];
    a->rel[0] = a->rel[1];
    a->rel[1] = t;
    return true;
}

static bool fr_rel_kind(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_rel) {
        return false;
    }
    (FUZZ_REL(r))->kind = (r & 1) ? TCG_CAP_NONE : TCG_CAP_UNSUPPORTED;
    return true;
}

/* Out of range for its kind, where its kind has a range. */
static bool fr_rel_val(FuzzArt *a, uint64_t r)
{
    for (int i = 0; i < a->h->n_rel; i++) {
        TCGCacheArtRel *x = &a->rel[(i + r) % a->h->n_rel];

        switch (x->kind) {
        case TCG_CAP_STUB:
            x->val = TCG_STUB_MAX;
            return true;
        case TCG_CAP_OWN_TB:
            x->val = tb_struct_size(a->h->nb_slots);
            return true;
        case TCG_CAP_HOT:
            x->val = a->h->hot_len + 4;
            return true;
        case TCG_CAP_COLD:
            x->val = a->h->cold_len + 4;
            return true;
        case TCG_CAP_HELPER:
            x->val = (uint64_t)1 << 40;
            return true;
        }
    }
    return false;
}

static bool fr_thunk_packed(FuzzArt *a, uint64_t r)
{
    if (a->h->flags & TCG_CACHE_ART_SPLIT || !a->h->n_rel) {
        return false;
    }
    (FUZZ_REL(r))->kind = TCG_CAP_THUNK;
    return true;
}

/* A slot matching @want: 0 live, 1 plain, 2 next (NOP), 3 trampoline. */
static int fuzz_slot(FuzzArt *a, uint64_t r, int want)
{
    for (int i = 0; i < a->h->nb_slots; i++) {
        int n = (i + r) % a->h->nb_slots;
        const TCGCacheArtSlot *sl = &a->slot[n];
        bool cold = (a->h->jmp_cold | a->h->jmp_call) & (1u << n);

        if (sl->insn == TB_JMP_OFFSET_INVALID) {
            continue;
        }
        if (want == 0 || (want == 1 && !cold)
            || (want == 2 && cold && sl->reset == sl->insn + 4)
            || (want == 3 && cold && sl->reset != sl->insn + 4)) {
            return n;
        }
    }
    return -1;
}

static bool fr_slot_dead(FuzzArt *a, uint64_t r)
{
    if (!a->h->nb_slots) {
        return false;
    }
    a->slot[r % a->h->nb_slots].dead = a->h->nb_slots + 1;
    return true;
}

/* dead naming a slot in range but unused: chaining would patch it. */
static bool fr_dead_unused(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 0);

    for (int m = 0; n >= 0 && m < a->h->nb_slots; m++) {
        if (a->slot[m].insn == TB_JMP_OFFSET_INVALID) {
            a->slot[n].dead = m + 1;
            return true;
        }
    }
    return false;
}

static bool fr_slot_insn(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 0);

    if (n < 0 || val_is_branch(ldl_he_p(a->hot))) {
        return false;
    }
    a->slot[n].insn = 0;
    return true;
}

static bool fr_slot_reset(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 0);

    if (n < 0) {
        return false;
    }
    a->slot[n].reset = (a->slot[n].reset & TCG_CACHE_COLD_BIT)
                       | (((a->slot[n].reset & TCG_CACHE_COLD_BIT)
                           ? a->h->cold_len : a->h->hot_len) + 4);
    return true;
}

static bool fr_slot_cond(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 3);

    if (n < 0) {
        return false;
    }
    a->slot[n].cond = a->h->hot_len + 8;
    return true;
}

static bool fr_slot_bits(FuzzArt *a, uint64_t r)
{
    if (a->h->nb_slots >= 8) {
        return false;
    }
    a->h->jmp_cold |= 1u << a->h->nb_slots;
    return true;
}

/* A cold slot's cond in the other part from the slot. */
static bool fr_cond_cross(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 3);
    uint32_t other;

    if (n < 0 || !(a->h->flags & TCG_CACHE_ART_SPLIT) || !a->h->cold_len) {
        return false;
    }
    other = (a->slot[n].insn & TCG_CACHE_COLD_BIT) ^ TCG_CACHE_COLD_BIT;
    a->slot[n].cond = 1 + other;
    return true;
}

/* A cold slot's cond a B.cond in its part that doesn't reach the slot. */
static bool fr_cond_target(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 3);
    uint32_t part, len;
    uint8_t *base;

    if (n < 0) {
        return false;
    }
    part = a->slot[n].insn & TCG_CACHE_COLD_BIT;
    base = part ? a->cold : a->hot;
    len = part ? a->h->cold_len : a->h->hot_len;
    for (uint32_t o = 0; o + 4 <= len; o += 4) {
        uintptr_t to;

        if (tcg_cache_decode(base + o, o, TCG_CAPF_BCOND19, 0, &to)
            && to != (a->slot[n].insn & ~TCG_CACHE_COLD_BIT)) {
            a->slot[n].cond = 1 + (part | o);
            return true;
        }
    }
    return false;
}

/* A slot with a trampoline made a call slot without one. */
static bool fr_call_notramp(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 2);

    if (n < 0) {
        n = fuzz_slot(a, r, 3);
        if (n < 0) {
            return false;
        }
        a->slot[n].reset = a->slot[n].insn + 4;
        a->slot[n].cond = 0;
        a->h->jmp_far &= ~(1u << n);
    }
    a->h->jmp_cold &= ~(1u << n);
    a->h->jmp_call |= 1u << n;
    return true;
}

/* The trampoline's BR made a BR x17. */
static bool fr_tramp_br(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 3);

    if (n < 0) {
        return false;
    }
    stl_he_p(fuzz_at(a, a->slot[n].reset - 4), VAL_BR_X16 | (1 << 5));
    return true;
}

/* The trampoline's load made a load of another register. */
static bool fr_tramp_ldr(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 3);
    uint32_t tsz;
    uint8_t *p;

    if (n < 0) {
        return false;
    }
    tsz = a->h->jmp_far & (1u << n) ? 12 : 8;
    p = fuzz_at(a, a->slot[n].reset - tsz);
    stl_he_p(p, ldl_he_p(p) ^ 1);
    return true;
}

/* A plain slot's BR made a NOP. */
static bool fr_plain_br(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 1);

    if (n < 0) {
        return false;
    }
    stl_he_p(fuzz_at(a, a->slot[n].insn + 4), VAL_NOP);
    return true;
}

static bool fr_con_slot(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_con) {
        return false;
    }
    a->con[r % a->h->n_con].slot = a->h->nb_slots;
    return true;
}

static bool fr_con_site(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_con) {
        return false;
    }
    a->con[r % a->h->n_con].site += 4;
    return true;
}

static bool fr_con_kind(FuzzArt *a, uint64_t r)
{
    if (!a->h->n_con) {
        return false;
    }
    a->con[r % a->h->n_con].kind = TCG_CAPC_SLOT_LDRLIT + 1;
    return true;
}

/* A plain slot's constraint removed. */
static bool fr_con_missing(FuzzArt *a, uint64_t r)
{
    size_t off;

    if (!a->h->n_con) {
        return false;
    }
    off = (uint8_t *)&a->con[r % a->h->n_con] - a->b;
    fuzz_splice(a, off, sizeof(TCGCacheArtCon), NULL, 0);
    ((TCGCacheArt *)a->b)->n_con--;
    return fuzz_view(a);
}

/* A constraint for a slot that isn't plain. */
static bool fr_con_extra(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 3);
    TCGCacheArtCon c;

    if (n < 0) {
        n = fuzz_slot(a, r, 2);
    }
    if (n < 0) {
        return false;
    }
    c = (TCGCacheArtCon){ .site = a->slot[n].insn,
                          .kind = TCG_CAPC_SLOT_LDRLIT, .slot = n };
    fuzz_splice(a, (uint8_t *)a->con - a->b, 0, &c, sizeof(c));
    ((TCGCacheArt *)a->b)->n_con++;
    return fuzz_view(a);
}

static bool fr_icount_more(FuzzArt *a, uint64_t r)
{
    a->h->icount++;
    return true;
}

static bool fr_search_unterminated(FuzzArt *a, uint64_t r)
{
    memset(a->search, 0x80, a->h->search_len);
    return a->h->search_len > 0;
}

/* Row 0's host offset past the code. */
static bool fr_search_host(FuzzArt *a, uint64_t r)
{
    return fuzz_rows_set(a, INSN_START_WORDS, a->h->pool_off + 4);
}

/* Row 0's CC_OP, past what the target stores. */
static bool fr_insn_ccop(FuzzArt *a, uint64_t r)
{
    return INSN_START_WORDS > 1 && fuzz_rows_set(a, 1, 0x7fffffff);
}

/* Row 0's third word: a YMM-clear mask naming a register past 31. */
static bool fr_insn_ymm(FuzzArt *a, uint64_t r)
{
    return INSN_START_WORDS > 2 && fuzz_rows_set(a, 2, 1ll << 47);
}

/* Row 0's second word, a value inside the range the target refuses. */
static bool fr_insn_gap(FuzzArt *a, uint64_t r)
{
    uint64_t v;

    if (INSN_START_WORDS < 2 || !tcg_cache_insn_nbad) {
        return false;
    }
    v = tcg_cache_insn_bad[r % tcg_cache_insn_nbad];
    return fuzz_rows_set(a, 1, v);
}

/* A slot's reset label moved to where the pool starts, or the end. */
static bool fr_reset_pool(FuzzArt *a, uint64_t r)
{
    int n = fuzz_slot(a, r, 0);

    if (n < 0 || (a->slot[n].reset & TCG_CACHE_COLD_BIT)) {
        return false;
    }
    a->slot[n].reset = a->h->pool_off;
    return true;
}

/* A writeback whose type doesn't match the global at its place. */
static bool fr_lazy_type(FuzzArt *a, uint64_t r)
{
    uint8_t *w = fuzz_first_wb(a);

    if (!w || (w[2] != TCG_TYPE_I32 && w[2] != TCG_TYPE_I64)) {
        return false;
    }
    w[2] = w[2] == TCG_TYPE_I32 ? TCG_TYPE_I64 : TCG_TYPE_I32;
    return true;
}

/* A writeback from another base register. */
static bool fr_lazy_base(FuzzArt *a, uint64_t r)
{
    uint8_t *w = fuzz_first_wb(a);

    if (!w) {
        return false;
    }
    w[1] ^= 1;
    return true;
}

typedef struct FuzzCase {
    const char *name;
    FuzzRule fn;
    int want;           /* the check expected to catch it */
    int alt;            /* another that may, as the damage allows */
} FuzzCase;

static const FuzzCase fuzz_cases[] = {
    { "no-extents", fr_no_ext, TCG_CACHE_V_LIMIT },
    { "extent-order", fr_ext_order, TCG_CACHE_V_EXTENT },
    { "extent-touch", fr_ext_touch, TCG_CACHE_V_EXTENT },
    { "extent-short", fr_ext_short, TCG_CACHE_V_EXTENT },
    { "extent-far", fr_ext_far, TCG_CACHE_V_EXTENT },
    { "extent-head", fr_ext_head, TCG_CACHE_V_EXTENT },
    { "size0", fr_size0, TCG_CACHE_V_SPAN },
    { "page2-flag", fr_page2, TCG_CACHE_V_SPAN },
    { "icount0", fr_icount0, TCG_CACHE_V_LIMIT },
    { "icount+1", fr_icount_more, TCG_CACHE_V_UNWIND, TCG_CACHE_V_INSN },
    { "flags", fr_flags, TCG_CACHE_V_HEADER },
    { "pad", fr_pad, TCG_CACHE_V_HEADER },
    { "split-cold", fr_split_cold, TCG_CACHE_V_HEADER },
    { "rel-misalign", fr_rel_misalign, TCG_CACHE_V_REL_SITE },
    { "rel-form", fr_rel_form, TCG_CACHE_V_REL_FORM },
    { "rel-raw-adrp", fr_rel_raw, TCG_CACHE_V_REL_FORM },
    { "rel-aux", fr_rel_aux, TCG_CACHE_V_REL_FORM },
    { "rel-out", fr_rel_out, TCG_CACHE_V_REL_SITE },
    { "rel-canon", fr_rel_canon, TCG_CACHE_V_REL_CANON },
    { "rel-order", fr_rel_order, TCG_CACHE_V_REL_ORDER },
    { "rel-kind", fr_rel_kind, TCG_CACHE_V_REL_TARGET },
    { "rel-val", fr_rel_val, TCG_CACHE_V_REL_TARGET },
    { "thunk-packed", fr_thunk_packed, TCG_CACHE_V_REL_TARGET },
    { "slot-dead", fr_slot_dead, TCG_CACHE_V_SLOT },
    { "dead-unused", fr_dead_unused, TCG_CACHE_V_SLOT },
    { "slot-insn", fr_slot_insn, TCG_CACHE_V_SLOT },
    { "slot-reset", fr_slot_reset, TCG_CACHE_V_SLOT },
    { "slot-cond", fr_slot_cond, TCG_CACHE_V_SLOT },
    { "slot-bits", fr_slot_bits, TCG_CACHE_V_SLOT },
    { "cond-cross", fr_cond_cross, TCG_CACHE_V_SLOT },
    { "cond-target", fr_cond_target, TCG_CACHE_V_SLOT },
    { "call-notramp", fr_call_notramp, TCG_CACHE_V_SLOT },
    { "tramp-br", fr_tramp_br, TCG_CACHE_V_SLOT },
    /* A far trampoline's ADRP: its LDR no longer consumes it. */
    { "tramp-ldr", fr_tramp_ldr, TCG_CACHE_V_SLOT, TCG_CACHE_V_REL_FORM },
    { "plain-br", fr_plain_br, TCG_CACHE_V_SLOT },
    { "con-slot", fr_con_slot, TCG_CACHE_V_CON },
    { "con-site", fr_con_site, TCG_CACHE_V_CON },
    { "con-kind", fr_con_kind, TCG_CACHE_V_CON },
    { "con-missing", fr_con_missing, TCG_CACHE_V_CON },
    { "con-extra", fr_con_extra, TCG_CACHE_V_CON },
    { "search-unterminated", fr_search_unterminated, TCG_CACHE_V_UNWIND },
    { "search-host", fr_search_host, TCG_CACHE_V_UNWIND },
    { "insn-ccop", fr_insn_ccop, TCG_CACHE_V_INSN },
    { "insn-ymm", fr_insn_ymm, TCG_CACHE_V_INSN },
    { "insn-gap", fr_insn_gap, TCG_CACHE_V_INSN },
    { "reset-pool", fr_reset_pool, TCG_CACHE_V_SLOT },
    { "lazy-type", fr_lazy_type, TCG_CACHE_V_LAZY },
    { "lazy-base", fr_lazy_base, TCG_CACHE_V_LAZY },
};

static uint64_t fuzz_rng(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* Known answers: LEB128 bounds and XXH64. The number failing. */
static int fuzz_known(void)
{
    static const int64_t vals[] = {
        0, 1, -1, 63, 64, -64, -65, INT32_MAX, INT32_MIN,
        (int64_t)1 << 40, INT64_MAX, INT64_MIN, INT64_MIN + 1,
    };
    static const uint8_t bad[][11] = {
        /* Ten bytes, the last 0x7e or 0x01: past 64 bits. */
        { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7e },
        { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 },
        /* Eleven. */
        { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 },
    };
    static const size_t bad_len[] = { 10, 10, 11 };
    static const struct {
        const char *s;
        size_t n;
        uint64_t h;
    } kat[] = {
        { "", 0, 0xef46db3751d8e999ull },
        { "a", 1, 0xd24ec4f1a98c6e5bull },
        { "abc", 3, 0x44bc2cf5ad770999ull },
    };
    uint8_t buf[16], r100[100];
    int fails = 0;

    for (int i = 0; i < ARRAY_SIZE(vals); i++) {
        const uint8_t *p = buf, *end = fuzz_sleb_enc(buf, vals[i]);
        int64_t x;

        if (!val_sleb(&p, end, &x) || x != vals[i] || p != end) {
            fprintf(stderr, "xtcg-cache fuzz: leb %" PRId64 " wrong\n",
                    vals[i]);
            fails++;
        }
    }
    for (int i = 0; i < ARRAY_SIZE(bad); i++) {
        const uint8_t *p = bad[i];
        int64_t x;

        if (val_sleb(&p, bad[i] + bad_len[i], &x)) {
            fprintf(stderr, "xtcg-cache fuzz: bad leb %d accepted\n", i);
            fails++;
        }
    }
    for (int i = 0; i < ARRAY_SIZE(kat); i++) {
        if (tcg_cache_hash64(0, kat[i].s, kat[i].n) != kat[i].h) {
            fprintf(stderr, "xtcg-cache fuzz: xxh64 \"%s\" wrong\n",
                    kat[i].s);
            fails++;
        }
    }
    for (int i = 0; i < 100; i++) {
        r100[i] = i;
    }
    if (tcg_cache_hash64(0, r100, 100) != 0x6ac1e58032166597ull) {
        fprintf(stderr, "xtcg-cache fuzz: xxh64 of 0..99 wrong\n");
        fails++;
    }
    fprintf(stderr, "xtcg-cache fuzz: known answers: %d failures\n", fails);
    return fails;
}

typedef struct FuzzSel {
    int n;
    uint64_t content[TCG_CACHE_CANDS];
} FuzzSel;

static bool fuzz_sel_use(const TCGCacheEnv *env, void *opaque)
{
    FuzzSel *u = opaque;

    u->content[u->n++] = env->content;
    return false;
}

static const uint8_t *fuzz_sel_base;
static uint64_t fuzz_sel_other_rva;

/* By hash, then the forged (another key's envelopes) first. */
static int fuzz_sel_cmp(const void *a, const void *b)
{
    const TCGCacheIdx *x = a, *y = b;
    bool fx = ((const TCGCacheEnv *)(fuzz_sel_base + x->off))->rva
              == fuzz_sel_other_rva;
    bool fy = ((const TCGCacheEnv *)(fuzz_sel_base + y->off))->rva
              == fuzz_sel_other_rva;

    if (x->khash != y->khash) {
        return x->khash < y->khash ? -1 : 1;
    }
    return fy - fx;
}

/*
 * The lookup's selection on a forged segment: for one key, five index
 * entries whose envelopes have another key, three copies of one artifact
 * (two born on other days), then a distinct artifact of the same key.
 * Selection must pass exactly the two distinct ones.  The number of
 * failures.
 */
static int fuzz_select(const TCGCacheEnv *e, const TCGCacheEnv *other)
{
    size_t al = e->len - sizeof(*e), ol = other->len - sizeof(*other);
    size_t cap = 16 * (ROUND_UP(e->len, 8) + ROUND_UP(other->len, 8));
    uint8_t *data = g_malloc0(cap), *art2;
    size_t dl = 0, flen;
    TCGCacheArtView v;
    TCGCacheFile f;
    TCGCacheIdx *idx;
    FuzzSel u = { };
    void *file, *buf = g_malloc(sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX);
    uint64_t kh = key_hash(e->id, e->rva, e->flags, e->cs_base, e->cflags);
    int fails = 0;

    for (int i = 0; i < 5; i++) {
        dl += tcg_cache_envelope(data + dl, other->id, other->rva, other->born,
                                 other + 1, ol);
    }
    for (int i = 0; i < 3; i++) {
        dl += tcg_cache_envelope(data + dl, e->id, e->rva, e->born + i,
                                 e + 1, al);
    }
    /* A distinct artifact of the same key: one guest byte differs. */
    art2 = g_memdup2(e + 1, al);
    if (tcg_cache_art_view(art2, al, &v) && v.h->ext_bytes) {
        ((uint8_t *)v.ext_bytes)[0] ^= 1;
    }
    dl += tcg_cache_envelope(data + dl, e->id, e->rva, e->born, art2, al);
    file = tcg_cache_write_file(false, 1, data, dl, NULL, 0, &flen);
    if (!file || tcg_cache_file_open(&f, file, flen, tcg_cache_gcopy,
                                     tcg_cache_nofault)) {
        fprintf(stderr, "xtcg-cache fuzz: select: no file\n");
        fails++;
        goto out;
    }
    /* Forge the five others' entries to the key, keeping order. */
    idx = (TCGCacheIdx *)((uint8_t *)file + f.hdr.index_off);
    for (uint32_t i = 0; i < f.hdr.n_index; i++) {
        const TCGCacheEnv *x = (const void *)((uint8_t *)file + idx[i].off);

        if (x->id == other->id && x->rva == other->rva) {
            idx[i].khash = kh;
            idx[i].check = key_check(e->rva, e->flags);
        }
    }
    /* The forged entries first in the key's run, so they're met first. */
    fuzz_sel_base = file;
    fuzz_sel_other_rva = other->rva;
    qsort(idx, f.hdr.n_index, sizeof(*idx), fuzz_sel_cmp);
    tcg_cache_file_select(&f, e->id, e->rva, e->flags, e->cs_base, e->cflags,
                          buf, sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX,
                          fuzz_sel_use, &u, NULL);
    if (u.n != 2 || u.content[0] == u.content[1]) {
        fprintf(stderr, "xtcg-cache fuzz: select passed %d candidates\n",
                u.n);
        fails++;
    }
    tcg_cache_file_close(&f);
out:
    fprintf(stderr, "xtcg-cache fuzz: selection: %d failures\n", fails);
    g_free(file);
    g_free(art2);
    g_free(data);
    g_free(buf);
    return fails;
}

int tcg_cache_fuzz_file(const void *map, size_t size, uint64_t seed,
                        unsigned arts)
{
    TCGCacheFile f;
    uint8_t *snap, *copy;
    size_t bufsz = sizeof(TCGCacheEnv) + TCG_CACHE_ART_MAX;
    uint8_t *buf;
    uint64_t base_counts[TCG_CACHE_V_MAX] = { }, c[TCG_CACHE_V_MAX];
    uint64_t rng = seed | 1, undetected = 0, flips = 0, tried = 0;
    uint64_t sem[3][TCG_CACHE_V_MAX] = { }, sem_tried[3] = { };
    unsigned applied[ARRAY_SIZE(fuzz_cases)] = { };
    unsigned caught[ARRAY_SIZE(fuzz_cases)] = { };
    unsigned other[ARRAY_SIZE(fuzz_cases)] = { };
    unsigned accepted[ARRAY_SIZE(fuzz_cases)] = { };
    uint32_t n, base_ok, find_miss = 0;
    int fails = fuzz_known(), r;

    /* A bounded snapshot, read through the guarded copy. */
    if (size > TCG_CACHE_FILE_MAX) {
        fprintf(stderr, "xtcg-cache fuzz: file too large\n");
        return fails + 1;
    }
    snap = g_malloc(size);
    if (tcg_cache_gcopy(snap, map, size)) {
        fprintf(stderr, "xtcg-cache fuzz: file changed under its mapping\n");
        g_free(snap);
        return fails + 1;
    }
    /* The file as it is: everything must pass. */
    if (tcg_cache_check_file(snap, size, false, base_counts)
        || tcg_cache_file_open(&f, snap, size, tcg_cache_gcopy,
                               tcg_cache_nofault)) {
        fprintf(stderr, "xtcg-cache fuzz: the undamaged file fails\n");
        g_free(snap);
        return fails + 1;
    }
    copy = g_malloc(size);
    buf = g_malloc(bufsz);
    base_ok = base_counts[TCG_CACHE_V_OK];
    n = f.hdr.magic == TCG_CACHE_PACK_MAGIC ? 1u << f.hdr.slot_log2
                                             : f.hdr.n_index;

    /* Every artifact is found by its key, through the lookup's path. */
    for (uint32_t i = 0; i < n; i++) {
        TCGCacheIdx e, got[TCG_CACHE_PROBES];
        TCGCacheEnv hdr;
        bool found = false;
        int k;

        if (!file_entry(&f, i, &e) || !e.khash
            || !file_read(&f, e.off, &hdr, sizeof(hdr))) {
            continue;
        }
        k = tcg_cache_file_find(&f, hdr.id, hdr.rva, hdr.flags, hdr.cs_base,
                                hdr.cflags, got, TCG_CACHE_PROBES);
        for (int j = 0; j < k; j++) {
            found |= got[j].off == e.off;
        }
        find_miss += !found;
    }
    fprintf(stderr, "xtcg-cache fuzz: %u artifacts not found by key\n",
            find_miss);
    fails += find_miss;

    /* The selection loop, on two of the file's artifacts. */
    {
        TCGCacheEnv *two[2] = { };
        int got = 0;

        for (uint32_t i = 0; i < n && got < 2; i++) {
            TCGCacheIdx e;
            TCGCacheEnv hdr;
            const TCGCacheEnv *env;

            if (!file_entry(&f, i, &e) || !e.khash
                || !file_read(&f, e.off, &hdr, sizeof(hdr))
                || tcg_cache_file_get(&f, &e, hdr.id, hdr.rva, hdr.flags,
                                      hdr.cs_base, hdr.cflags, buf, bufsz,
                                      &env)
                || (got && two[0]->rva == env->rva)) {
                continue;
            }
            two[got++] = g_memdup2(env, env->len);
        }
        if (got == 2) {
            fails += fuzz_select(two[0], two[1]);
        }
        g_free(two[0]);
        g_free(two[1]);
    }

    /* Truncation at evenly spread lengths. */
    for (size_t step = MAX(size / 4096, 1), l = 0; l < size; l += step) {
        memset(c, 0, sizeof(c));
        tcg_cache_check_file(snap, l, true, c);
        tried++;
    }
    fprintf(stderr, "xtcg-cache fuzz: %" PRIu64 " truncations survived\n",
            tried);

    /* Raw bit flips: an envelope flipped must not pass. */
    for (unsigned k = 0; k < 4096; k++) {
        size_t at = fuzz_rng(&rng) % size;
        bool in_env = false;

        memcpy(copy, snap, size);
        copy[at] ^= 1 << (fuzz_rng(&rng) & 7);
        for (uint32_t i = 0; i < n && !in_env; i++) {
            TCGCacheIdx e;

            if (file_entry(&f, i, &e) && e.khash && at >= e.off
                && at < (uint64_t)e.off + e.len) {
                in_env = true;
            }
        }
        memset(c, 0, sizeof(c));
        tcg_cache_check_file(copy, size, true, c);
        flips++;
        if (in_env && c[TCG_CACHE_V_OK] >= base_ok) {
            undetected++;
        }
    }
    fprintf(stderr, "xtcg-cache fuzz: %" PRIu64 " bit flips, %" PRIu64
            " inside an envelope undetected\n", flips, undetected);
    fails += undetected;

    /* Each artifact damaged on purpose, then validated directly. */
    for (uint32_t i = 0, done = 0; i < n && done < arts; i++) {
        TCGCacheIdx e;
        TCGCacheEnv hdr;
        const TCGCacheEnv *env;
        FuzzArt a = { };
        size_t alen;

        if (!file_entry(&f, i, &e) || !e.khash
            || !file_read(&f, e.off, &hdr, sizeof(hdr))
            || tcg_cache_file_get(&f, &e, hdr.id, hdr.rva, hdr.flags,
                                  hdr.cs_base, hdr.cflags, buf, bufsz,
                                  &env)) {
            continue;
        }
        done++;
        alen = env->len - sizeof(*env);
        for (int t = 0; t < ARRAY_SIZE(fuzz_cases); t++) {
            uint64_t rr = fuzz_rng(&rng);

            a.b = g_memdup2(env + 1, alen);
            a.len = alen;
            if (fuzz_view(&a) && fuzz_cases[t].fn(&a, rr)) {
                applied[t]++;
                r = tcg_cache_validate(a.b, a.len);
                if (r == fuzz_cases[t].want) {
                    caught[t]++;
                } else if (r && r == fuzz_cases[t].alt) {
                    caught[t]++;
                } else if (r) {
                    other[t]++;
                    if (tcg_cache_debug) {
                        fprintf(stderr, "xtcg-cache fuzz: %s caught by %s"
                                " at pc %" PRIx64 "\n", fuzz_cases[t].name,
                                tcg_cache_v_name(r), a.h->pc);
                    }
                } else {
                    accepted[t]++;
                    if (tcg_cache_debug) {
                        fprintf(stderr, "xtcg-cache fuzz: %s accepted at pc %"
                                PRIx64 "\n", fuzz_cases[t].name, a.h->pc);
                    }
                }
            }
            g_free(a.b);
        }
        /* Random bytes: metadata, code, unwind data. */
        a.b = g_memdup2(env + 1, alen);
        a.len = alen;
        if (fuzz_view(&a)) {
            size_t meta = a.v.hot - (const uint8_t *)a.v.h;
            size_t code = a.v.search - a.v.hot;
            size_t srch = a.h->search_len;
            size_t lo[3] = { 0, meta, meta + code };
            size_t len3[3] = { meta, code, srch };

            for (int part = 0; part < 3; part++) {
                for (int k = 0; k < 32 && len3[part]; k++) {
                    uint8_t *m = g_memdup2(env + 1, alen);

                    m[lo[part] + fuzz_rng(&rng) % len3[part]] = fuzz_rng(&rng);
                    sem[part][tcg_cache_validate(m, alen)]++;
                    sem_tried[part]++;
                    g_free(m);
                }
            }
        }
        g_free(a.b);
    }
    for (int t = 0; t < ARRAY_SIZE(fuzz_cases); t++) {
        fprintf(stderr, "xtcg-cache fuzz: %-20s applied %5u caught %5u"
                " OTHER %u ACCEPTED %u%s\n", fuzz_cases[t].name, applied[t],
                caught[t], other[t], accepted[t],
                applied[t] ? "" : " (not applicable to this file)");
        fails += accepted[t] + other[t];
    }
    for (int part = 0; part < 3; part++) {
        static const char *const pn[] = { "metadata", "code", "unwind" };

        fprintf(stderr, "xtcg-cache fuzz: %" PRIu64 " random %s bytes:",
                sem_tried[part], pn[part]);
        for (int i = 0; i < TCG_CACHE_V_MAX; i++) {
            if (sem[part][i]) {
                fprintf(stderr, " %s=%" PRIu64, tcg_cache_v_name(i),
                        sem[part][i]);
            }
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "xtcg-cache fuzz: %d failures\n", fails);
    tcg_cache_file_close(&f);
    g_free(snap);
    g_free(copy);
    g_free(buf);
    return fails;
}
#else
/* No artifacts to damage without the back end's support. */
int tcg_cache_fuzz_file(const void *map, size_t size, uint64_t seed,
                        unsigned arts)
{
    return 1;
}
#endif /* TCG_TARGET_HAS_CACHE */

TCGCacheFile tcg_cache_loaded;
bool tcg_cache_have_loaded;

typedef struct StoreOut {
    uint8_t *buf;
    size_t len, cap;
    uint32_t born;
} StoreOut;

static void store_out_one(void *opaque, uint64_t id, uint64_t rva,
                          uint64_t base, const void *art, size_t len)
{
    StoreOut *o = opaque;
    size_t need = ROUND_UP(sizeof(TCGCacheEnv) + len, 8);

    if (len > TCG_CACHE_ART_MAX) {
        return;
    }
    if (o->len + need > o->cap) {
        o->cap = MAX(o->cap * 2, o->len + need);
        o->buf = g_realloc(o->buf, o->cap);
    }
    o->len += tcg_cache_envelope(o->buf + o->len, id, rva, o->born, art,
                                 len);
}

void *tcg_cache_store_envelopes(uint32_t born, size_t *lenp)
{
    StoreOut o = { .born = born };

    tcg_cache_store_foreach(store_out_one, &o);
    *lenp = o.len;
    return o.buf;
}
