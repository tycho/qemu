/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Recording a captured translation's place-dependent sites (tcg-cache.h),
 * for the back end's emitters.  Every PC-relative encoder records its
 * site with the provenance its caller set (s->cap_kind), else none; an
 * emitter that puts a relocatable value into an absolute form records the
 * site and the value itself.  Nothing here changes the code emitted.
 */

#ifndef TCG_CACHE_REC_H
#define TCG_CACHE_REC_H

#include "tcg/tcg-cache.h"

/* Data inside code (the slow-thunk descriptor): aux is its length. */
#define TCG_CAPF_DATA   (TCG_CAPF_MAX + 1)
/* A constraint (TCG_CAPC_*, in kind), aux its slot. */
#define TCG_CAPF_CON    (TCG_CAPF_MAX + 2)

typedef struct TCGCapRec {
    void *site;             /* RW */
    uint8_t form;
    uint8_t kind;
    uint16_t aux;
    uintptr_t val;          /* absolute forms: the value encoded */
} TCGCapRec;

#define TCG_CAP_MAXREC  4096

static void tcg_cap_fail(TCGContext *s, unsigned reason)
{
    if (s->cap_on && !s->cap_fail) {
        s->cap_fail = reason;
    }
}

static void __attribute__((noinline))
tcg_cap_rec_slow(TCGContext *s, void *site, int form, int kind,
                 uint16_t aux, uintptr_t val)
{
    TCGCapRec *r;

    if (s->cap_nrec == s->cap_maxrec) {
        if (s->cap_maxrec == TCG_CAP_MAXREC) {
            tcg_cap_fail(s, TCG_CACHE_X_TOO_MANY);
            return;
        }
        s->cap_maxrec = s->cap_maxrec ? s->cap_maxrec * 2 : 256;
        s->cap_rec = g_renew(TCGCapRec, s->cap_rec, s->cap_maxrec);
    }
    r = &s->cap_rec[s->cap_nrec++];
    r->site = site;
    r->form = form;
    r->kind = kind;
    r->aux = aux;
    r->val = val;
}

/* A site with the current provenance. */
static inline void tcg_cap_rec(TCGContext *s, void *site, int form)
{
    if (unlikely(s->cap_on)) {
        tcg_cap_rec_slow(s, site, form, s->cap_kind, 0, 0);
    }
}

/* A site with its own provenance, aux and value. */
static inline void tcg_cap_rec_k(TCGContext *s, void *site, int form,
                                 int kind, uint16_t aux, uintptr_t val)
{
    if (unlikely(s->cap_on)) {
        tcg_cap_rec_slow(s, site, form, kind, aux, val);
    }
}

/*
 * A call's target: a stub generated in the code buffer, or a function in
 * QEMU's image.
 */
static inline int tcg_cap_kind_of(TCGContext *s, const void *target_rx)
{
    return in_code_gen_buffer((const char *)target_rx - tcg_splitwx_diff)
           ? TCG_CAP_STUB : TCG_CAP_HELPER;
}

/* The provenance of the next emissions, until reset with TCG_CAP_NONE. */
static inline void tcg_cap_prov(TCGContext *s, int kind)
{
    s->cap_kind = kind;
}

#endif
