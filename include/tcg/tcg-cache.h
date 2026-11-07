/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Translation artifacts: a TB's code and metadata as a self-contained
 * record that can be installed again at another place in the code buffer.
 *
 * While a translation is captured, the back end records every site whose
 * encoding depends on where the code lies, with what the value at that
 * site means (its provenance): a helper, a stub generated at start-up, the
 * TB's own struct, the chunk's slow-path thunk, a place in the TB's own
 * code, or a value that must stay as it is.  A PC-relative reference whose
 * meaning isn't known fails the capture.  The front end records the guest
 * bytes the translation read, the sites it ordered with acquire/release,
 * and anything that makes the translation unfit to keep.
 */

#ifndef TCG_CACHE_H
#define TCG_CACHE_H

#include "exec/vaddr.h"

typedef struct TCGContext TCGContext;
typedef struct TranslationBlock TranslationBlock;

/* tcg_cache_mode */
enum {
    TCG_CACHE_OFF,
    TCG_CACHE_CAPTURE,      /* record and check; install nothing */
    TCG_CACHE_STRESS,       /* install every captured TB from its artifact */
};

extern int tcg_cache_mode;
/* Development: move each install by up to this many 16-byte steps. */
extern unsigned tcg_cache_skew;
extern bool tcg_cache_stats_at_exit;
extern bool tcg_cache_debug;

/*
 * Why a translation isn't captured.  Front-end reasons latch for the
 * whole translation attempt; back-end ones for an emission attempt.
 */
enum {
    TCG_CACHE_X_NONE,
    TCG_CACHE_X_SMC,        /* an SMC check in the TB */
    TCG_CACHE_X_REGION,     /* a region head, trial or probation counter */
    TCG_CACHE_X_PROMOTED,   /* a promoted TSO crossing site */
    TCG_CACHE_X_HOSTPTR,    /* a host pointer as an IR constant */
    TCG_CACHE_X_PLUGIN,
    TCG_CACHE_X_TORN,       /* a guest byte read twice, differently */
    TCG_CACHE_X_SPAN,       /* a guest read outside the TB's two pages */
    TCG_CACHE_X_FAKE,       /* bytes not read from guest memory */
    TCG_CACHE_X_FRONT_MAX,
    /* Back end */
    TCG_CACHE_X_UNKNOWN_REF = TCG_CACHE_X_FRONT_MAX, /* outward, no meaning */
    TCG_CACHE_X_RAW_ADRP,   /* an ADRP without a declared consumer */
    TCG_CACHE_X_ORR_PTR,    /* a relocatable value as a logical immediate */
    TCG_CACHE_X_POOL_MIX,   /* pool dedup merged different meanings */
    TCG_CACHE_X_UNSUPPORTED,/* an emitter that can't be relocated */
    TCG_CACHE_X_TOO_MANY,   /* the record list overflowed */
    TCG_CACHE_X_PROV,       /* a recorded meaning didn't match the code */
    TCG_CACHE_X_LAZY,       /* lazy-sync data outside the hot part */
    TCG_CACHE_X_VERIFY,     /* the verifier found an unrecorded site */
    TCG_CACHE_X_MAX
};

extern const char *const tcg_cache_x_names[TCG_CACHE_X_MAX];

/* Provenance: what the value at a site is. */
enum {
    TCG_CAP_NONE,           /* not declared */
    TCG_CAP_ABS,            /* the value itself, unchanged */
    TCG_CAP_HELPER,         /* code or data in QEMU's image */
    TCG_CAP_STUB,           /* code generated at start-up (TCG_STUB_*) */
    TCG_CAP_OWN_TB,         /* the TB's struct (RX alias), plus an addend */
    TCG_CAP_THUNK,          /* the chunk's slow-path thunk */
    TCG_CAP_HOT,            /* a place in the TB's hot part */
    TCG_CAP_COLD,           /* a place in the TB's cold part */
    TCG_CAP_UNSUPPORTED,
};

enum {
    TCG_STUB_EPILOGUE0,     /* tcg_code_gen_epilogue */
    TCG_STUB_RET,           /* the epilogue's return path, tb_ret_addr */
    TCG_STUB_XPAGE,         /* tcg_xpage_stub */
    TCG_STUB_MAX
};

/* Forms: how a site encodes its value. */
enum {
    TCG_CAPF_NONE,
    TCG_CAPF_B26,           /* B, BL */
    TCG_CAPF_BCOND19,       /* B.cond, CBZ, CBNZ */
    TCG_CAPF_TBZ14,         /* TBZ, TBNZ */
    TCG_CAPF_LDRLIT19,      /* LDR (literal) */
    TCG_CAPF_ADR21,         /* ADR */
    TCG_CAPF_ADRP,          /* ADRP alone: a page-aligned value */
    TCG_CAPF_ADRP_ADD,      /* ADRP, then ADD of the low 12 bits */
    TCG_CAPF_ADRP_LDR,      /* ADRP, then LDR (unsigned offset), scaled */
    TCG_CAPF_RAW_ADRP,      /* ADRP whose consumer wasn't declared */
    TCG_CAPF_MOVW,          /* MOVZ or MOVN, then MOVKs (aux below) */
    TCG_CAPF_POOL64,        /* a 64-bit pool word */
    TCG_CAPF_REL32,         /* a 32-bit offset from the word to the target */
    TCG_CAPF_MAX
};

/* TCG_CAPF_MOVW's aux: the halfwords set, MOVN first, 64-bit. */
#define TCG_CAP_MOVW_MASK   0xf
#define TCG_CAP_MOVW_MOVN   0x10
#define TCG_CAP_MOVW_X      0x20

/* Constraints that later patching relies on. */
enum {
    TCG_CAPC_SLOT_LDRLIT = 1,   /* the slot reaches its target_addr by LDR */
};

/*
 * The serialized artifact.  Every offset is from the artifact's start;
 * every multi-byte field is in host order.
 */
#define TCG_CACHE_MAGIC     0x41435458      /* "XTCA" */
#define TCG_CACHE_VERSION   1

/* TCGCacheArt.flags */
#define TCG_CACHE_ART_SPLIT     1   /* hot and cold parts (tcg_tblayout) */
#define TCG_CACHE_ART_PAGE2     2   /* the TB uses the next page too */

/* A place in the TB: bit 31 says the cold part. */
#define TCG_CACHE_COLD_BIT      0x80000000u

typedef struct TCGCacheArt {
    uint32_t magic;
    uint32_t len;
    uint16_t version;
    uint16_t flags;
    uint16_t nb_slots;
    uint16_t n_rel;
    uint16_t n_con;
    uint16_t n_acq;
    uint16_t n_ext;
    uint16_t size;
    uint16_t icount;
    uint16_t jmp_call;
    uint8_t jmp_cold;
    uint8_t jmp_far;
    uint8_t loops;
    uint8_t edge_end;
    uint8_t chain_dead_in;
    uint8_t pad[3];
    uint32_t tb_flags;
    uint32_t cflags;
    uint64_t pc;
    uint64_t cs_base;
    uint32_t hot_len;       /* code and pool */
    uint32_t pool_off;      /* where the pool starts, or hot_len */
    uint32_t cold_len;      /* cold code */
    uint32_t search_len;    /* unwind data, after the cold code */
    uint32_t ext_bytes;     /* the guest bytes of all extents */
    uint32_t pad2;
} TCGCacheArt;

typedef struct TCGCacheArtSlot {
    uint32_t reset;         /* a place, or TB_JMP_OFFSET_INVALID */
    uint32_t insn;          /* a place, or TB_JMP_OFFSET_INVALID */
    uint32_t cond;          /* 0, or 1 + a place */
    uint8_t dead;
    uint8_t pad[3];
} TCGCacheArtSlot;

typedef struct TCGCacheArtRel {
    uint32_t site;          /* a place */
    uint8_t form;
    uint8_t kind;
    uint16_t aux;
    uint64_t val;           /* by kind: offset, stub, addend, value, place */
} TCGCacheArtRel;

typedef struct TCGCacheArtCon {
    uint32_t site;          /* a place */
    uint8_t kind;
    uint8_t slot;
    uint16_t pad;
} TCGCacheArtCon;

typedef struct TCGCacheArtExt {
    uint16_t off;           /* from the page of pc */
    uint16_t len;
} TCGCacheArtExt;

/* The artifact's arrays and parts, located and bounds-checked. */
typedef struct TCGCacheArtView {
    const TCGCacheArt *h;
    const TCGCacheArtSlot *slot;
    const TCGCacheArtRel *rel;
    const TCGCacheArtCon *con;
    const uint64_t *acq;
    const TCGCacheArtExt *ext;
    const uint8_t *ext_bytes;
    const uint8_t *hot;
    const uint8_t *cold;
    const uint8_t *search;
} TCGCacheArtView;

bool tcg_cache_art_view(const void *art, size_t len, TCGCacheArtView *v);

/* Front end, during translation (with tcg_ctx->cap_on). */
void tcg_cache_tb_start(TCGContext *s, vaddr pc_first, unsigned page_bits);
void tcg_cache_exclude(TCGContext *s, unsigned reason);
void tcg_cache_read(TCGContext *s, vaddr pc, const void *p, size_t len);
void tcg_cache_acqrel(TCGContext *s, uint64_t pc);

/*
 * After translation, before the TB is published: the artifact (g_free
 * it), its length in *@lenp; or NULL, the reason counted.  @search is the
 * unwind data's RW address.
 */
void *tcg_cache_capture(TCGContext *s, TranslationBlock *tb,
                        const void *search, size_t search_len, size_t *lenp);

/*
 * Install: reserve the TB's places in the current layout (nothing moves
 * until commit), place and relocate it, then commit or abort.
 */
typedef struct TCGCacheRes {
    void *tb;               /* RW */
    void *hot;              /* RW */
    void *cold;             /* RW: cold code, then the unwind data */
    void *search;           /* RW */
    void *code_gen_ptr;     /* after commit */
    void *lay_cold;         /* after commit, split layout */
    const void *thunk;
    bool split;
} TCGCacheRes;

bool tcg_cache_reserve(TCGContext *s, const TCGCacheArtView *v,
                       TCGCacheRes *r);
TranslationBlock *tcg_cache_place(TCGContext *s, const TCGCacheArtView *v,
                                  const TCGCacheRes *r);
void tcg_cache_commit(TCGContext *s, const TCGCacheRes *r);

/* Counters, printed at exit with XTCG_CACHE_STATS. */
typedef struct TCGCacheStats {
    uint64_t tried, captured, bytes, excluded[TCG_CACHE_X_MAX];
    uint64_t installs, inst_fail_reserve, inst_fail_reloc, inst_fail_bytes;
    uint64_t inst_fail_con, inst_fail_promoted, inst_fail_key, inst_dup;
    uint64_t rel_kind[TCG_CAP_UNSUPPORTED + 1], rel_form[TCG_CAPF_MAX];
    uint64_t hot_bytes, cold_bytes, search_bytes, ext_total;
    uint64_t capture_ns, install_ns;
} TCGCacheStats;

extern TCGCacheStats tcg_cache_stats;
void tcg_cache_print_stats(void);

#endif
